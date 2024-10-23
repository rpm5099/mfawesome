import datetime
import functools
import os
import sys
import time
import types

import rich

from mfawesome.exception import ScreenResizeError
from mfawesome.utils import PRINT, IsIPython, clear_output_ex, clear_output_line, colors, get_term_size, gettime, hms, systimestr


def Countdown(s: str = "Timer Expires in: ", t: int = 10, showsystime: bool = True) -> None:
    while t > 0:
        timer = hms(t)
        if showsystime:
            systemtime = colors("green", gettime())
            print(f"{s} {timer}    System Time: {systemtime}", end="\r")
        else:
            print(f"{s} {timer}", end="\r")
        time.sleep(1)
        t -= 1
    clear_output_line()


class CountdownBar:
    def __init__(
        self,
        msg: str = "",
        timertime: float = 30.0,
        freq: float = 0.1,
        fixedbartime: float = 30.0,
        barchar: str = "=",
        filler: str = ".",
    ) -> None:
        self.timertime = float(timertime)
        self.fixedbartime = fixedbartime
        if (not self.fixedbartime) or self.fixedbartime < self.timertime:
            self.fixedbartime = self.timertime
        self._remaining = float(self.timertime)
        self._barwidth = None
        self.barchar = barchar
        self.freq = freq
        self.filler = filler
        self.msg = msg

    @property
    def barwidth(self) -> int:
        termsize = ProgBar.get_term_size()[0] - 70
        if self._barwidth is not None and termsize != self._barwidth:
            raise ScreenResizeError("The screen appears to have been resized")
        self._barwidth = termsize
        return self._barwidth

    @staticmethod
    def systimestr() -> str:
        return colors("green", f"   System Time: {gettime()}")

    def _print(self, s) -> None:
        sys.stdout.write("\r" + get_term_size()[0] * " ")
        sys.stdout.write("\r")
        sys.stdout.flush()
        sys.stdout.write(s + "\r")
        sys.stdout.flush()

    @staticmethod
    def _clear_output_line() -> None:
        sys.stdout.write("\r" + get_term_size()[0] * " ")
        sys.stdout.write("\r")
        sys.stdout.flush()

    @staticmethod
    def hms(s: str, n: float) -> str:
        ts = str(datetime.timedelta(seconds=int(n))) + "s"
        if n < 11.0 and n >= 6.0:
            return colors("orange", s + ts)
        if n < 6.0:
            return colors("bold_red", s + ts)
        return colors("green", s + ts)

    def _bar(self, prog: float) -> str:
        gone = self.barwidth - prog
        return CountdownBar.hms(f"[{self.barchar * prog}{gone * self.filler}] {self.msg}", self._remaining) + CountdownBar.systimestr()

    def begin(self) -> None:
        while self._remaining > 0:
            prog = int(self.barwidth * (self._remaining / self.fixedbartime))
            self._print(self._bar(prog))
            time.sleep(self.freq)
            self._remaining -= self.freq
        newline = "\n"
        CountdownBar._clear_output_line()
        sys.stdout.write(
            f"{colors('max_red', '[' + self.barwidth * self.filler + '] ' + self.msg)} {hms(self._remaining)}{CountdownBar.systimestr()}{newline}",
        )


def DoubleCountdown(
    s1: str = "Timer 1 Expires in: ",
    t1: float = 5.5,
    s2: str = "Timer 2 Expires in: ",
    t2: float = 8.0,
    increment: float = 0.5,
    killonfirst: bool = False,
    showsystime: bool = True,
) -> None:
    maxt = max([t1, t2])

    endtime = colors("max_red", "00:00:00")
    while maxt > 0:
        timer1 = hms(t1)
        if t1 <= 0:
            timer1 = endtime
        timer2 = hms(t2)
        if t2 <= 0:
            timer2 = endtime
        if showsystime:
            systemtime = colors("green", gettime())
            print(f"{s1} {timer1}   {s2} {timer2}   System Time: {systemtime}", end="\r")
        else:
            print(f"{s1} {timer1}   {s2} {timer2}", end="\r")
        if killonfirst and (t1 <= 0 or t2 <= 0):
            return
        time.sleep(increment)
        t1 -= increment
        t2 -= increment
        maxt -= increment
    print(f"{s1} {endtime}   {s2} {endtime}")


class ProgBar:
    def __init__(
        self,
        msg: str = "Time remaining",
        timertime: float = 30.0,
        freq: float = 0.2,
        fixedbartime: float = 30.0,
        barchar: str = "=",
        filler: str = ".",
    ) -> None:
        self.timertime = float(timertime)
        self.fixedbartime = fixedbartime
        if (not self.fixedbartime) or self.fixedbartime < self.timertime:
            self.fixedbartime = self.timertime
        self.remaining = float(self.timertime)
        self.barchar = barchar
        self.freq = freq
        self.filler = filler
        self.msg = msg + ": "
        self._barwidth = None

    @staticmethod
    def get_term_size(defaultwidth: int = 150, defaultheight: int = 50) -> tuple[int, int]:
        try:
            width, height = os.get_terminal_size()
            return width, height
        except OSError as e:
            # probably in jupyter
            return defaultwidth, defaultheight

    @property
    def barwidth(self) -> float:
        termsize = ProgBar.get_term_size()[0] - 70
        if self._barwidth is not None and termsize != self._barwidth:
            raise ScreenResizeError("The screen appears to have been resized")
        self._barwidth = termsize
        return self._barwidth

    @staticmethod
    def hms(s: str, n: float) -> str:
        ts = str(datetime.timedelta(seconds=int(n))) + "s"
        if n < 11.0 and n >= 6.0:
            return colors("orange", s + ts)
        if n < 6.0:
            return colors("bold_red", s + ts)
        return colors("green", s + ts)

    def bar(self, remaining: None = None) -> str:
        self.remaining = remaining if remaining is not None else self.remaining
        self.remaining = max(0, self.remaining)
        prog = int(self.barwidth * (self.remaining / self.fixedbartime))
        gone = self.barwidth - prog
        return ProgBar.hms(f"{self.msg:20.20}  [{self.barchar * prog}{gone * self.filler}]  ", self.remaining)

    def update(self, seconds: None = None) -> None:
        val = seconds if seconds is not None else self.freq
        self.remaining -= val


HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"

# Blinking "\033[5m"

if IsIPython():
    from IPython import get_ipython
    from IPython.display import clear_output, display

    def doDisplay(*args: list, **kwargs: dict) -> None:
        global PRINT
        isinstance(PRINT, types.BuiltinFunctionType)
        displaypartial = functools.partial(display, *args)
        if kwargs.pop("flush") is True:
            sys.stdout.flush()
        PRINT = displaypartial


class CountdownBars:
    """
    Example Usage:
    t1 = ProgBar(msg="Bar1", systime=True)
    t2 = ProgBar(msg="Bar2", timertime=35, fixedbartime=90)
    t3 = ProgBar(msg=" YEAH", timertime=17, fixedbartime=20)
    progbars = [t1, t2, t3]
    bars = CountdownBars(progbars, textabove="Here's some progress bars", textbelow="This is below the bars")
    bars.begin()
    OR to manually update the bars and not use bars.begin():


    while bars.Completed is False:
        bars.update()
        time.sleep(bars.freq)
    """

    def __init__(
        self,
        progbars: list[ProgBar] | ProgBar,
        freq: float = 0.2,
        systime: bool = True,
        textabove: str | None = None,
        textbelow: str | None = None,
        killonfirst: bool = True,
    ) -> None:
        if not isinstance(progbars, list):
            self.progbars = [progbars]
        else:
            self.progbars = progbars
        self.barcount = len(self.progbars)
        if killonfirst:
            self.remtime = min([bar.remaining for bar in self.progbars])
        else:
            self.remtime = max([bar.remaining for bar in self.progbars])
        self.freq = freq
        for bar in self.progbars:
            bar.freq = self.freq
        self.ipython = IsIPython()
        # if self.ipython:
        #     self.freq = 0.5
        self.textabove = textabove
        self.textbelow = textbelow
        self.started = False
        self._termwidth = get_term_size()[0]
        self.systime = systime
        sys.stdout.write(HIDE_CURSOR)
        sys.stdout.flush()
        self.finaloutput = False
        # self.msgpad = max([len(pb.msg) for pb in self.progbars])
        print("\n\n")

    @property
    def termwidth(self) -> int:
        termsize = get_term_size()[0]
        if termsize != self._termwidth:
            raise ScreenResizeError("The screen appears to have been resized")
        self._termwidth = termsize
        return self._termwidth

    @property
    def Completed(self) -> bool:
        if self.remtime > 0:
            return False
        if self.remtime <= 0 and self.finaloutput is False:
            self.finaloutput = True
            return False
        sys.stdout.write("\n")
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.flush()
        return True

    def _display(self) -> None:
        if self.ipython:
            clear_output(wait=False)

            if self.textabove:
                if isinstance(self.textabove, rich.table.Table):
                    rich.console.Console().print(self.textabove, end="\r")
                    # sys.stdout.flush()
                else:
                    print(self.textabove)  # , flush=True)
            for bar in self.progbars:
                PRINT(bar.bar(), flush=True)
                # print("\n", flush=True)
            if self.textbelow:
                PRINT(self.textbelow, flush=True)
        else:
            outputs = []
            if self.textabove:
                outputs.append(self.textabove)
            for bar in self.progbars:
                outputs.append(bar.bar())  # noqa: PERF401
            if self.textbelow:
                outputs.append(self.textbelow)
            if self.systime:
                outputs.append(systimestr())
            else:
                PRINT("\n\n")
            goback = "\033[F"
            PRINT(goback * (len(outputs) + 1))
            for output in outputs:
                PRINT(output)
            sys.stdout.flush()
        self.started = True

    def begin(self) -> None:
        if self.Completed:
            raise RuntimeError("All bars have completed")
        while self.Completed is False:
            self._display()
            for bar in self.progbars:
                bar.update(self.freq)
            self.remtime -= self.freq
            time.sleep(self.freq)

    def update(self, seconds: float | None = None, textabove: str | None = None, textbelow: str | None = None) -> None:
        increment = seconds if seconds is not None else self.freq
        self.textabove = textabove if textabove is not None else self.textabove
        self.textbelow = textbelow if textbelow is not None else self.textbelow
        for bar in self.progbars:
            bar.remaining -= increment
        self._display()
        self.remtime -= increment
