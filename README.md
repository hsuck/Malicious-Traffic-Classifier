# Malicious-Traffic-Classifier
## Table of contents
* [Platforms](##platforms)
* [Dependencies](##Dependencies)
* [Execution](##Execution)
## Platforms
You should be able to execute the program on the following platforms:
* Ubuntu 20.04
## Dependencies
* The latest version of numpy (1.21.1 or greater)
* The latest version of [pytorch](https://pytorch.org/) **with compute platform on CUDA 10.2/11.3**
```
pip3 install -r requirement.txt
```
## Execution
To execute the program, you should create a new environment used to install all package in need first. 
```
virtualenv your_env_name
```
This command will create a virtual environment upon the directory where you run the command. Once you've created a virtual environment, you may activate it.
```
source your_env_name/bin/activate
```
Finally, after installing all packages listed above, you'll be able to execute the program with an argument specified the network interface.
```
python3 main.py network_interface_name
```