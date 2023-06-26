from .utils import *
from .log import log
from .log import Color

import signal

class devAV():

    def __init__(self, verbosity, timeout, ignoresignal = False):
        """
        Initialize the devAV object.

        Args:
            verbosity (int): Level of verbosity for logging. Higher values result in more detailed logs.
            timeout (int): Timeout value for scanning operations.
        """
        self.verbosity = verbosity
        self.timeout = timeout

        if ignoresignal:
            check_model()
            return

        signal.signal(signal.SIGINT, self.signal_handler)

        check_model()

    def signal_handler(self, signal, frame):
        """
        Handles the SIGINT signal (Ctrl+C event).

        Args:
            signal (int): Signal number.
            frame (frame): Current stack frame (unused in this function).
        """
        print('You pressed Ctrl+C!')
        sys.exit(0)

    def scan(self, filepath):
        """
        Scans the provided filepath for malware.

        This function logs the scan process and utilizes the simple voting
        system to determine if the binary at the provided filepath is malware.
        Based on verbosity settings, it either returns votes directly or after
        generating more detailed logs.

        Args:
            filepath (str): Path to the file to be scanned.

        Returns:
            votes: An integer or tuple (based on the simple voting system and
                   error handling) indicating the detection results.
        """

        if self.verbosity > 0:
            log("i", f"Scanning {filepath}")
        votes = -1
        error = None
        try:
            votes = simple_voting_system(filepath, verbosity=self.verbosity, timeout=self.timeout)
            if self.verbosity < 1:
                return votes
        except Exception as error:
            if type(votes) is int and votes < 0:
                log("e", f"Error with {filepath}: {error}")
                return votes

        if type(votes) is not tuple or votes[0] is None:
            log("e", f"Error with {filepath}")
            return votes

        log("s", "Scanning successful")
        for key, value in votes[0].items():
            ret = "Malware"
            if value == 0:
                ret = "No Malware"
            if value<0:
                ret = "Error"

            print("\t", end="")
            log("s", f"{key.capitalize()} model: {ret}")

        if votes[1]:
            log("w", f"File mostly detected as {Color.RED}MALWARE{Color.END}")
            return votes

        log("s", f"devAV {Color.GREEN}DOES NOT DETECT MALWARE{Color.END}")
        return votes


    def prob_scan(self, filepath):
        """
        Scans the provided filepath for malware.

        This function logs the scan process and utilizes the probabilistic
        system to determine the malware probabilities for the binary at the
        provided filepath. It prints the predictions for each model.

        Args:
            filepath (str): Path to the file to be scanned.
        """

        if self.verbosity > 0:
            log("i", f"Scanning {filepath}")

        try:
            prob_predictions = probabilistic_system(filepath, timeout=self.timeout)

            # Printing the prediction probabilities
            malware_probs = []
            for key, value in prob_predictions.items():
                if type(value) is not dict:
                    continue
                log("i", f"{key.capitalize()} model:")
                for class_name, prob in value.items():
                    if class_name == 1:
                        malware_probs.append(prob)
                        class_name = f"{Color.RED}Malware{Color.END}"
                    elif class_name == 0:
                        class_name = f"{Color.GREEN}Beningware{Color.END}"
                    log("s", f"\tClass {class_name}: {round(prob, 3)}")
                print()

            # Calculate the mean of malware probabilities
            mean_malware_prob = sum(malware_probs) / len(malware_probs)
            print()
            log("w", f"{Color.RED}MALWARE{Color.END} with a probability of {round(mean_malware_prob, 3)}")
            log("s", f"{Color.GREEN}BENINGWARE{Color.END} with a probability of {round(1 - mean_malware_prob, 3)}")

        except Exception as error:
            log("e", f"Error with {filepath}: {error}")
            return
