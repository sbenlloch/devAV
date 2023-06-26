import argparse
from .core import devAV

def main():
    parser = argparse.ArgumentParser(description='Scan for malware using devAV.')
    parser.add_argument('filepath', metavar='F', type=str, nargs=1,
                        help='a filepath to scan')
    parser.add_argument('--verbosity', default=3, type=int,
                        help='set the level of verbosity')
    parser.add_argument('--timeout', default=None, type=int,
                        help='set a timeout')
    parser.add_argument('-p', '--prob', default=False, action='store_true',
                        help='set a timeout')

    args = parser.parse_args()

    if args.prob:
        scanner = devAV(args.verbosity, args.timeout)
        results = scanner.prob_scan(args.filepath[0])
        return None

    scanner = devAV(args.verbosity, args.timeout)
    results = scanner.scan(args.filepath[0])

    return None

if __name__ == "__main__":
    main()

