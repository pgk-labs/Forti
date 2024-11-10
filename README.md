FortiFlex: A Comprehensive FortiGate Configuration Management Tool

FortiFlex is a powerful Python-based tool designed to simplify the configuration and management of FortiGate devices via API. With FortiFlex, users can effortlessly manage configurations, handle multiple Virtual Domains (VDOMs), rename interfaces, migrate configurations between devices, and perform seamless configuration downloads and uploads.

Table of Contents

1. Features
	-Print Configuration Sections
	-Multi-VDOM Management
	-Rename FortiGate Interfaces (Alias)
	-Migrate Configuration from a Source Device
	-Download Configuration
	-Upload Configuration
2. Installation
3. Configuration
4. Usage
5. Directory Structure
6. Contribution Guidelines
7. License
8. Contact


1. Features FortiFlex includes the following key features:

a. Print Configuration Sections: View, select,download, send and delete specific configuration from a FortiGate device. 
b. Multi-VDOM Management: Enabling / disabling multi-vdom functionality. 
c. Rename FortiGate Interfaces (Alias): Update interface names using aliases. 
d. Migrate Configuration: Copy configurations from one FortiGate device to another, with automatic dependency checking. 
e. Download Configuration: Save the current FortiGate configuration to a local file for backup or review. 
f. Upload Configuration: Apply new configurations by uploading a saved configuration file to a FortiGate device.

2. Installation Prerequisites Ensure you have the following:
Python 3.6 or later Access to a FortiGate device with API access enabled or user credentials. Installation Steps

Clone the repository:

git clone https://github.com/pgk-labs/FortiFlex.git
cd FortiFlex 

Install dependencies: Run the following command to install all required libraries:
pip install -r requirements.txt

Set up configuration: In the project’s root directory, a named folder should be created and then a .yaml file is required with the below key-value pairs. This file should store your FortiGate API credentials and connection details.

3. Configuration In your config.yaml file, add your FortiGate device's IP address and API key as follows: 

host: '192.168.1.1' 
username: 'apiuser' 
local_username: 'localuser' 
password: 'localpassword' 
api_key: 'apikey'

Replace the values with your actual FortiGate details.

4. Usage Once installed, you can start FortiFlex by running the main Python file:
python fortiflex.py You’ll be prompted with a menu to select specific functionalities.

5. Directory Structure Here’s an overview of the directory structure for easy navigation:

FortiFlex/

errors/   # containing a .json file with all errors the fortiosAPI can give(or at least what I have found)

sections/ # The configuration sections in order to be able to explore fortigate's sections.

yaml/     # Yaml folder which contains the appropriate formated .yaml files in order to connect to the fortigate device(s).

screenshots/ # Some screenshots

README.md    # Project documentation

requirements.txt # Dependencies

fortiflex.py     # The basic .py file.

6. Contribution Guidelines Contributions to FortiFlex are welcome! Here’s how to contribute:

Fork this repository. Create a new branch with a descriptive name for your feature or bug fix:

git checkout -b feature-branch-name Commit your changes and push to your forked repository. Create a pull request with a description of your changes. Please ensure that all new code includes proper documentation and comments to make it understandable for future contributors.

7. License This project is licensed under the MIT License - see the LICENSE file for details.

8. Contact For questions, feedback, or issues, feel free to reach out:

GitHub Issues: Please open an issue if you encounter any problems. Email: pgkerdidanis@hotmail.com



Validate the changes before every action. I am not responsible for misconfigurations on the fortigate devices. 
