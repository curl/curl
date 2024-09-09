#!env python3
import re
from sys import stdin


def main():
    testnr = None
    durations = {}
    for l in stdin.readlines():
        m = re.match(r'test (\d+)\..*', l)
        if m:
            testnr = int(m.group(1))
            continue
        m = re.match(r'^[-a-z]+ .*took (\d+(\.\d+))s,.*', l)
        if m:
            if testnr is None:
                raise f'Error: no test number set for: {l}'
            if testnr in durations:
                raise f'Error: duration for test {testnr} already set'
            durations[testnr] = float(m.group(1))
            continue
        print(f'unmatched: {l}')
    print('test durations')
    for nr, duration in sorted(durations.items(), key=lambda item: item[1]):
        print(f'{nr}: {duration}s')


if __name__ == "__main__":
    main()
