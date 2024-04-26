# README #

This repo contains a prototype implementation of HCT framework as well as scripts for reproducing the experiments shown in the paper.

#### How do I get set up? ####
1. Clone the repo.
2. Open a terminal into the cloned folder.
2. Create a virtual environment in the cloned repo folder:
	* ```virtualenv -p python3.8.2 my_env```
3. Activate virtual environment.
	* ```source my_env/bin/activate```
4. Make sure python 3.8.2 is installed by issuing:
	* ```python --version```
5. Install all dependencies by issuing:
	* 	```pip3 install -r requirements.txt```

#### HCT Prototype ####
To run and test the prototype implementation issue the following command.
* ```python3 HCT.py```

#### Calculate prob. of n common CTs (1<=n<=40 or 80) for 2-5 breached servers (Figs. 7 & 8) ####
Note: It takes around 1-2 hours to complete on a normal PC.
* ```python3 prob_common_CTs_different_servers.py```

#### Calculate prob. of depth- & breadth-first attacks in breaching a target account or causing a false brech alarm ####
* ```python3 success_prob_breach_or_trigger_false_alarm_table1.py```

#### Calculate average no. of accounts to be created by online adversaries to trigger decoys only and alert a false breach alarm####
* ```python3 accounts_to_create_for_false_breach_alarm.py```


