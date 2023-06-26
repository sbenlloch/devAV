# 🛡️ devAV: Application of machine learning to security

![Python package](https://github.com/sg1o/devAV/actions/workflows/python-package.yml/badge.svg)
![Python 3.10](https://img.shields.io/badge/Python-3.10-3776AB?logo=python&logoColor=white)
![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![Tested on Ubuntu Latest](https://img.shields.io/badge/Tested%20on-Ubuntu%20Latest-E95420?logo=ubuntu&logoColor=white)

> **Warning** This repository is part of a master thesis project. It is possible that there may be errors or incomplete functions: we deeply appreciate your patience and constructive comments!

## 🎯 Purpose & Scope

`devAV` is a comprehensive toolkit for crafting a machine learning-based malware detector. It covers all aspects of application development: from data mining and feature extraction, to model selection and prototype deployment. Although a functional prototype, `devAV` is not intended to replace professional antivirus software.

## 🧠 Model Descriptions

`devAV` leverages various techniques to classify files as malware or benign. Here's a brief overview of the utilized models:

- **Functions**: Uses imported functions for classification.
- **Strings**: Employs a BERT model to extract features from strings for classification.
- **Mnemonics**: Classifies based on the frequency of mnemonics per instruction type groups.
- **Entropy**: Uses the entropy of sections within a binary file for characterization and classification.
- **Generic**: Performs classification based on basic characteristics of PE and ELF files.

To ensure the most reliable outcome, `devAV` applies a **Voting System** for final decision-making. This involves utilizing the results from the aforementioned models, each casting a "vote" on the file's classification. The majority vote decides the final outcome.

## 📊 Data & Results

Our testing involved a dataset of 21,090 files, comprising 10,739 malware and 10,351 benignware files. The ensuing performance metrics were impressive:

|   Metric   | Functions | Entropy | Strings | Generic | Mnemonics | Voting |
|:----------:|:---------:|:-------:|:-------:|:-------:|:---------:|:------:|
|  Accuracy  |   0.925   |  0.961  |  0.955  |  0.770  |   0.783   |  0.966 |
| Precision  |   0.881   |  0.949  |  0.977  |  0.713  |   0.557   |  0.951 |
|   Recall   |   0.986   |  0.976  |  0.934  |  0.917  |   0.667   |  0.985 |
|  F1 Score  |   0.931   |  0.963  |  0.955  |  0.803  |   0.607   |  0.968 |

The above statistics underscore the potential and effectiveness of machine learning in cybersecurity.

## 🚀 Installation & Setup

Clone the repository recursively to include the submodule:

```shell
git clone --recursive https://github.com/sg1o/devAV.git
```

Navigate into the project directory and install the project:

```shell
cd devAV
pip install -e .
```

Ensure that the required submodule is properly set up:

```shell
pip install -e binsniff/requirements.txt
```

Decompress the models available under `devav/models/compressed-files` using a 7z decompressor.

## 💻 Usage

Once installed, you can use the `devav` command to scan files:

```shell
devav --help
```

## 📝 Documentation

Additional documentation is available in the `docs` folder. Generate a live HTML version using:

```shell
make livehtml
```

## 👥 Contributing

Contributions are highly welcomed! If you spot a bug or would like to suggest improvements, feel free to open an issue or submit a pull request.

## 📃 License

This project is under the [GPL v3 License](LICENSE).
