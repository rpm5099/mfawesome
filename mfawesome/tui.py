from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Input, Static

from mfawesome import totpcore as _totp
from mfawesome.clipboard import copy as clipboard_copy
from mfawesome.config import FilterSecrets, SearchSecrets
from mfawesome.exception import Invalid2FACodeError, NoInternetError, NTPError, NTPInvalidServerResponseError
from mfawesome.utils import fix_b32decode_pad, gettime

logger = logging.getLogger("mfa.tui")


@dataclass
class _Row:
    name: str
    code: str
    nextcode: str
    user: str
    totp_secret: str
    password: str
    url: str
    valid: bool
    error: str = ""


def _calc_row(name: str, secretdata: dict, showerr: bool) -> _Row:
    totp_secret = secretdata.get("totp", "") or ""
    user = secretdata.get("user", "") or ""
    password = secretdata.get("password", "") or ""
    url = secretdata.get("url", "") or ""
    code = ""
    nextcode = ""
    valid = True
    err = ""
    try:
        if totp_secret:
            codes = _totp.multitotpcalc(totp_secret, codecount=2)
            code = codes[0].code
            nextcode = codes[1].code
    except (Invalid2FACodeError, NoInternetError, NTPError, NTPInvalidServerResponseError) as e:
        valid = False
        err = repr(e) if showerr else type(e).__name__
    return _Row(
        name=name,
        code=str(code),
        nextcode=str(nextcode),
        user=user,
        totp_secret=fix_b32decode_pad(totp_secret),
        password=password,
        url=url,
        valid=valid,
        error=err,
    )


def _fmt_seconds(seconds: float) -> str:
    """Format remaining time as raw seconds with one decimal, e.g. '27.4s'."""
    return f"{max(0.0, seconds):5.1f}s"


def _bar_color(remaining: float) -> str:
    if remaining < 6.0:
        return "bold red"
    if remaining < 11.0:
        return "orange3"
    return "green"


def _render_bar(label: str, remaining: float, total: float, width: int) -> str:
    """Render a Rich-markup progress bar that decreases as time runs out.

    [====....] label remaining_seconds / total_seconds
    At full time, bar is full; at expiration, bar is empty.
    Color thresholds match the original countdownbars scheme:
      green > 11s, orange 6-11s, red < 6s.
    """
    width = max(10, width)
    frac = 0.0 if total <= 0 else max(0.0, min(1.0, remaining / total))
    filled = int(width * frac)
    empty = width - filled
    color = _bar_color(remaining)
    return (
        f"[{color}][{'=' * filled}{'.' * empty}] "
        f"{label} {_fmt_seconds(remaining)} / {total:.0f}s[/{color}]"
    )


class MFAwesomeApp(App):
    CSS = """
    Screen { layout: vertical; background: #1E1E1E; }
    Header { height: 3; background: #264F78; color: #FFFFFF; text-style: bold; }
    #clock {
        height: 2;
        padding: 0 2;
        background: #1E1E1E;
        color: #4EC9B0;
        text-style: bold;
        content-align: right middle;
    }
    #status {
        height: 2;
        padding: 0 2;
        background: #1E1E1E;
        color: #DCDCAA;
        content-align: left middle;
    }
    #filter { display: none; height: 3; }
    #filter.visible { display: block; }
    DataTable {
        height: 1fr;
        background: #1E1E1E;
        color: #D4D4D4;
    }
    DataTable > .datatable--header {
        background: #264F78;
        color: #FFFFFF;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #264F78;
        color: #FFFFFF;
        text-style: bold;
    }
    .bar {
        height: 1;
        padding: 0 1;
    }
    Footer { background: #264F78; color: #FFFFFF; text-style: bold; }
    """

    BINDINGS = [
        Binding("c", "copy_code", "Copy code", show=True),
        Binding("space", "copy_code", "Copy", show=False),
        Binding("s", "toggle_secrets", "Show/Hide secrets", show=True),
        # +30s aliases. Numpad-+ sends different keysyms depending on terminal +
        # keypad mode (normal vs application). We bind every variant we know of.
        Binding("plus", "add_time", "+30s session", show=True),
        Binding("equals_sign", "add_time", "+30s session", show=False),
        Binding("shift+equals_sign", "add_time", "+30s session", show=False),
        Binding("right", "add_time", "+30s session", show=False),
        Binding("kp_add", "add_time", "+30s session", show=False),
        Binding("kp_plus", "add_time", "+30s session", show=False),
        Binding("kp_equal", "add_time", "+30s session", show=False),
        Binding("kp_right", "add_time", "+30s session", show=False),
        # -30s aliases (same reasoning for numpad).
        Binding("minus", "sub_time", "-30s session", show=True),
        Binding("hyphen_minus", "sub_time", "-30s session", show=False),
        Binding("left", "sub_time", "-30s session", show=False),
        Binding("kp_subtract", "sub_time", "-30s session", show=False),
        Binding("kp_minus", "sub_time", "-30s session", show=False),
        Binding("kp_left", "sub_time", "-30s session", show=False),
        Binding("slash", "start_filter", "Filter", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("ctrl+c", "quit", "Quit", show=False),
        Binding("escape", "cancel_filter", "Cancel filter", show=False),
    ]

    show_secrets: reactive[bool] = reactive(False)

    def __init__(
        self,
        secrets: dict,
        *,
        showsecrets: bool = False,
        showerr: bool = False,
        timelimit: float | None = None,
        filterterm: str | None = None,
        exact: bool = False,
    ) -> None:
        super().__init__()
        self._all_secrets = secrets
        self.show_secrets = showsecrets
        self.showerr = showerr
        # session always has a value; if None passed, codes-only single-cycle session of 30s
        self.session_total = float(timelimit) if timelimit is not None else 30.0
        self.session_remaining = self.session_total
        self._filterterm = filterterm
        self._exact = exact
        self._rows: list[_Row] = []
        self._names: list[str] = []
        self._secrets_filtered: dict = {}
        self._last_status_clear_at: float | None = None
        self._row_map: list[int | None] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("", id="clock", markup=True)
        yield Static("", id="status")
        yield Input(placeholder="Filter (Esc to cancel, Enter to apply)", id="filter")
        yield DataTable(id="table", cursor_type="row", zebra_stripes=False)
        yield Static("", id="codes-bar", classes="bar", markup=True)
        yield Static("", id="session-bar", classes="bar", markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "MFAwesome"
        self.sub_title = "Interactive TOTP"
        self._apply_filter(self._filterterm)
        self._build_table()
        self._refresh_rows()
        self._tick_progress()
        self.set_interval(0.2, self._tick_progress)
        self.set_interval(1.0, self._maybe_clear_status)
        table = self.query_one(DataTable)
        table.focus()

    def _apply_filter(self, term: str | None) -> None:
        secrets = SearchSecrets(term, self._all_secrets, exact=self._exact) if term else self._all_secrets
        secrets = FilterSecrets(secrets)
        names = sorted([k for k in secrets.keys() if "totp" in secrets[k]], key=str.casefold)
        self._secrets_filtered = secrets
        self._names = names

    def _build_table(self) -> None:
        table = self.query_one(DataTable)
        table.clear(columns=True)
        cols = ["Name", "Code", "Next", "User"]
        if self.show_secrets:
            cols += ["TOTP", "Password", "URL"]
        table.add_columns(*cols)

    def _refresh_rows(self) -> None:
        self._rows = [_calc_row(n, self._secrets_filtered[n], self.showerr) for n in self._names]
        self._repaint_table()

    def _repaint_table(self) -> None:
        table = self.query_one(DataTable)
        # Preserve which DATA row was focused, not which DataTable row.
        prev_data_idx = self._cursor_to_data_idx(table.cursor_row) if self._rows else 0
        table.clear()
        # Number of columns currently shown (used to size separator rows).
        n_cols = 4 + (3 if self.show_secrets else 0)
        sep_cell = "[dim]" + ("─" * 60) + "[/dim]"
        sep_row = [sep_cell] + [""] * (n_cols - 1)

        # Track which DataTable row index corresponds to which data row.
        # Separator rows get None.
        self._row_map: list[int | None] = []
        for i, r in enumerate(self._rows):
            if not r.valid:
                code = f"[bold red]ERROR ({r.error})[/bold red]"
                nextcode = "[bold red]ERROR[/bold red]"
            else:
                code = f"[bold green]{r.code}[/bold green]"
                nextcode = f"[grey53]{r.nextcode}[/grey53]"
            row_cells = [r.name, code, nextcode, r.user]
            if self.show_secrets:
                row_cells += [
                    f"[yellow]{r.totp_secret}[/yellow]",
                    f"[yellow]{r.password}[/yellow]",
                    f"[blue]{r.url}[/blue]",
                ]
            table.add_row(*row_cells, height=2)
            self._row_map.append(i)
            # Separator row after every data row except the last
            if i < len(self._rows) - 1:
                table.add_row(*sep_row, height=1)
                self._row_map.append(None)
        if self._rows:
            new_data_idx = min(prev_data_idx, len(self._rows) - 1)
            try:
                table.move_cursor(row=self._data_idx_to_row(new_data_idx))
            except Exception:
                pass

    def _cursor_to_data_idx(self, cursor_row: int) -> int:
        """Translate a DataTable cursor row index to a data row index, defaulting
        to nearest data row if cursor landed on a separator (shouldn't happen but safe)."""
        if not getattr(self, "_row_map", None):
            return 0
        if 0 <= cursor_row < len(self._row_map):
            v = self._row_map[cursor_row]
            if v is not None:
                return v
            # walk backward to nearest data row
            for j in range(cursor_row - 1, -1, -1):
                if self._row_map[j] is not None:
                    return self._row_map[j]
        return 0

    def _data_idx_to_row(self, data_idx: int) -> int:
        """Translate a data index to its DataTable row index."""
        for row_idx, d in enumerate(self._row_map):
            if d == data_idx:
                return row_idx
        return 0

    def _tick_progress(self) -> None:
        codes_remaining = _totp.RemainingTime()
        bar_width = max(20, self.size.width - 50)

        clock_widget = self.query_one("#clock", Static)
        clock_widget.update(f"System Time: {gettime()}")

        codes_widget = self.query_one("#codes-bar", Static)
        codes_widget.update(_render_bar("Codes Expire:", codes_remaining, 30.0, bar_width))

        if codes_remaining <= 0.3:
            self._refresh_rows()

        # Session counter: always counts down. Single-shot just shows codes timer mirrored.
        self.session_remaining = max(0.0, self.session_remaining - 0.2)
        session_widget = self.query_one("#session-bar", Static)
        session_widget.update(_render_bar("Session Expires:", self.session_remaining, self.session_total, bar_width))

        if self.session_remaining <= 0:
            self.exit()

    def _set_status(self, msg: str) -> None:
        self.query_one("#status", Static).update(msg)
        self._last_status_clear_at = time.monotonic() + 3.0

    def _maybe_clear_status(self) -> None:
        if self._last_status_clear_at and time.monotonic() >= self._last_status_clear_at:
            self.query_one("#status", Static).update("")
            self._last_status_clear_at = None

    def _focused_row_index(self) -> int | None:
        table = self.query_one(DataTable)
        if not self._rows:
            return None
        return self._cursor_to_data_idx(table.cursor_row)

    def on_key(self, event) -> None:
        """Safety net: catch any +/- variant our BINDINGS missed (e.g. numpad
        keys in application keypad mode that report unusual keysyms). Only
        fires for keys NOT already in BINDINGS (otherwise we'd double-dispatch).
        """
        # Don't intercept when typing in the filter input.
        if self.focused is not None and self.focused.id == "filter":
            return
        # Build set of all bound keys; skip if this key is already handled.
        bound_keys = set()
        for b in self.BINDINGS:
            bound_keys.update(b.key.split(","))
        if event.key in bound_keys:
            return
        k = (event.key or "").lower()
        if "plus" in k or k in {"+", "kp_add", "equals_sign"}:
            self.action_add_time()
            event.stop()
            return
        if "minus" in k or k in {"-", "kp_subtract", "hyphen_minus"}:
            self.action_sub_time()
            event.stop()
            return
        logger.info(f"Unbound key seen: {event.key!r}")

    def on_data_table_row_highlighted(self, event) -> None:
        """If the cursor landed on a separator row, bounce to the next data row
        in the same direction the user was moving."""
        if not self._row_map:
            return
        row = event.cursor_row
        if 0 <= row < len(self._row_map) and self._row_map[row] is None:
            # Determine direction by comparing to previous cursor (best-effort).
            # Default: bounce DOWN (skip the separator), or UP if at end.
            table = self.query_one(DataTable)
            if row + 1 < len(self._row_map) and self._row_map[row + 1] is not None:
                table.move_cursor(row=row + 1)
            elif row - 1 >= 0 and self._row_map[row - 1] is not None:
                table.move_cursor(row=row - 1)

    def action_copy_code(self) -> None:
        idx = self._focused_row_index()
        if idx is None or idx >= len(self._rows):
            self._set_status("No row to copy")
            return
        row = self._rows[idx]
        if not row.valid or not row.code:
            self._set_status(f"Cannot copy: {row.name} has no valid code")
            return
        ok, method = clipboard_copy(self, row.code)
        if ok:
            self._set_status(f"Copied code for '{row.name}' via {method}")
        else:
            self._set_status(f"Clipboard FAILED for '{row.name}' — see logs")

    def action_toggle_secrets(self) -> None:
        self.show_secrets = not self.show_secrets
        self._build_table()
        self._repaint_table()
        self._set_status(f"Secrets {'shown' if self.show_secrets else 'hidden'}")

    def action_add_time(self) -> None:
        self.session_total += 30.0
        self.session_remaining += 30.0
        self._set_status(f"+30s — session now {self.session_remaining:.0f}s")

    def action_sub_time(self) -> None:
        # Floor the total at 30s so the bar math stays sane; floor remaining at 0.
        self.session_total = max(30.0, self.session_total - 30.0)
        self.session_remaining = max(0.0, self.session_remaining - 30.0)
        self._set_status(f"-30s — session now {self.session_remaining:.0f}s")

    def action_start_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        inp.add_class("visible")
        inp.value = self._filterterm or ""
        inp.focus()

    def action_cancel_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        inp.remove_class("visible")
        self.query_one(DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "filter":
            return
        self._filterterm = event.value or None
        self._apply_filter(self._filterterm)
        self._refresh_rows()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "filter":
            return
        self.action_cancel_filter()


def run_tui(
    secrets: dict,
    *,
    showsecrets: bool = False,
    showerr: bool = False,
    timelimit: float | None = None,
    filterterm: str | None = None,
    exact: bool = False,
) -> None:
    """Launch the Textual TUI. Caller is responsible for calling totp.init() first."""
    app = MFAwesomeApp(
        secrets=secrets,
        showsecrets=showsecrets,
        showerr=showerr,
        timelimit=timelimit,
        filterterm=filterterm,
        exact=exact,
    )
    app.run()
