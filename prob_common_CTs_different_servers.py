"""
Calculate the probabilities of having n common CTs, 1 <= n <= 40 or 80, between no_servers_beached
(1 <= no_servers_beached <= 5) breached servers to which the target user has accounts with the same password
"""

import matplotlib.pyplot as plt
plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42
import numpy as np
import os
from colorama import  init
init(autoreset=True)
from HCT import compute_sha3_256_hash
from HCT import generate_random_integer
from HCT import calc_lists_of_tokens
from HCT import success_prob as p


def at_least_common_combos(no_servers_beached,window_size,p):
    """
    Calculates the probability of having n common combos, 1 <= n <= window_size, between no_servers_breached to which
    a user has accounts with the same password.
    :param no_servers_beached: he no. of breached servers to which the target user has account with the same password
    :param window_size: The no. of CTs per user
    :param p: The Bernoulli success probability (i.e., prob of selecting a CT as a decoy)
    :return: Outputs stats into a file called x-servers.txt
    """

    # placeholder parameters
    common_combos_options = [i for i in range(1,window_size+1)]
    common_combos = [0 for _ in range(len(common_combos_options))]
    total_combos = int(3.73 * pow(10,9))

    real_password = "password" # doesn't matter which password we choose -- the adjacent CTs are randomly selected

    # for each experiment create window_size CTs for each breached server to compare intersection
    no_of_experiments = 1000000  # repeat experiment 1M times
    for i in range(1,no_of_experiments+1):

        if i % 100000 == 0:
            # just to see intermediate progress
            print("Experiment no.: "+str(i))

        real_password_row = []
        for server_i in range(no_servers_beached):
            # produce the window_size tokens for server_i
            real_password_sha3_256_hash = compute_sha3_256_hash(real_password)  # get (sha3-256) digest of the password
            # print("SHA3-256 hash:", real_password_sha3_256_hash)
            valid_combo = generate_random_integer(real_password_sha3_256_hash.encode('utf-8'), 0, total_combos - 1)

            real_password_row.append(calc_lists_of_tokens(valid_combo, window_size, total_combos))

            if i % 100000 == 0:
                print("The user's valid combo at S" + str(server_i) + ": " + str(valid_combo))
                print("The user's sweet-token list at S" + str(server_i) + ":", real_password_row[server_i])

        # calculate the intersection between different servers' sweet-CT list
        intersection_row1 = set(real_password_row[0][0])  # convert first server's ct list to a set
        for server_i in range(1,len(real_password_row)):  # start from server 2 and get their intersection with first
            intersection_row1 &= set(real_password_row[server_i][0])
        intersection_row1 = list(intersection_row1)
        no_of_common_combos = len(intersection_row1)  # contains no. of common CTs between all servers

        # increase by 1 the counters for at least x common combos
        for z in range(0,common_combos_options.index(no_of_common_combos)+1):
            common_combos[z]+=1

        # intermediate saving of probabilities, just to monitor progress
        if i % 100000 == 0:
            # convert counters to probabilities
            probs = []
            for j in common_combos:
                probs.append(j / i)

            with open("probs_common_combos_exps/Bernoulli("+str(p)+")/"+str(window_size)+"/"+str(no_servers_beached)+"-servers.txt", "w") as file:
                file.write("Total number of experiments performed: " + str(i) + "\n")
                file.write("Probabilities of common combos between "+str(no_servers_beached)+" different servers:\n")
                for z in range(len(common_combos_options)):
                    file.write(str(common_combos_options[z])+" "+str(probs[z])+"\n")

        if i % 100000 == 0:
            print("=================")
            print()

    # convert counters to probabilities and save the final thing
    probs = []
    for i in common_combos:
        probs.append(i/no_of_experiments)
    with open("probs_common_combos_exps/Bernoulli("+str(p)+")/"+str(window_size)+"/"+str(no_servers_beached)+"-servers.txt", "w") as file:
        file.write("Total number of experiments performed: " + str(no_of_experiments) + "\n")
        file.write("Probabilities of common combos between "+str(no_servers_beached)+" different servers:\n")
        for z in range(len(common_combos_options)):
            file.write(str(common_combos_options[z]) + " " + str(probs[z]) + "\n")


def multiple_servers_graph_0(p,window_size):
    """
    Plots the probability vs. no. of common combos graph when 2, 3, 4 or 5 servers to which the target user has accounts
    with the same password have been compromised.
    :param p: The Bernoulli success probability
    :param window_size: The total no. of CTs per user
    :return:  None. Exports the graph with the probability of each no. of common combos per no. of breached servers.
    """

    directory_with_stats = "probs_common_combos_exps/Bernoulli("+str(p)+")/"+str(window_size)+"/"
    onlyfiles = ['2-servers.txt', '3-servers.txt', '4-servers.txt',  '5-servers.txt']

    all_probs = []
    for stats_file in onlyfiles:
        print(stats_file)

        with open(directory_with_stats+stats_file, "r") as file:
            lines = file.readlines()

        lines = lines[2:]  # exclude experiments details
        for i in range(len(lines)):
            lines[i] = lines[i].strip("\n")  # strip new line characters

        probs = []
        no_combos = []
        for i in range(len(lines)):
            tmp = lines[i].split(" ")
            no_combos.append(int(tmp[0]))
            probs.append(float(tmp[1]))

        probs = np.array(probs)

        all_probs.append(probs)
        no_combos = np.array(no_combos)

    fig, ax = plt.subplots()
    ax.autoscale_view()

    x_points_1=[]
    y_points_1=[]
    x_points_1.append(5)
    x_points_1.append(5)
    x_points_1.append(10)
    x_points_1.append(15)
    y_points_1.append(0.861068)
    y_points_1.append(0.109589)
    y_points_1.append(0.399781)
    y_points_1.append(0.039651)

    plt.vlines(x_points_1, 0, y_points_1, linestyle="dotted", colors='k')
    plt.hlines(y_points_1, 0, x_points_1, linestyle="dotted", colors='k')

    plt.xticks(np.append(no_combos[::19],(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19)),np.append(no_combos[::19],(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19)))
    y_labels = [ 0.109589, 0.109589, 0.2, 0.3, 0.4, 0.5,  0.6,  0.7, 0.8, 1.0, 0.861068, 0.861068, 0.399781, 0.039651, 0.039651, 0.9,   0.00517]
    y_labels_t = ['0.11', '0.11', '0.2', '0.3', '0.4', '0.5', '0.6','0.7','0.8', '1.0', '0.86', '0.86', '0.4', '0.04', '0.04', '0.9', '0.005']
    plt.yticks(y_labels,y_labels_t)

    plt.xlim([1, 19])
    plt.ylim([0, 1.02])

    # plot experimental results
    for i in range(len(all_probs)):
        plt.plot(no_combos, all_probs[i], "--", markerfacecolor='None', label=onlyfiles[i].strip(".txt"))

    plt.ylabel("Probability")
    plt.xlabel("No. of common CTs")
    plt.legend(loc="upper right", prop={'size': 10}, frameon=False)

    plt.show()


def multiple_servers_graph_1(p,window_size):
    """
    Plots the probability vs. no. of common combos graph when 2, 3, 4 or 5 servers to which the target user has accounts
    with the same password have been compromised.
    :param p: The Bernoulli success probability
    :param window_size: The total no. of CTs per user
    :return:  None. Exports the graph with the probability of each no. of common combos per no. of breached servers.
    """

    directory_with_stats = "probs_common_combos_exps/Bernoulli("+str(p)+")/"+str(window_size)+"/"
    onlyfiles = ['2-servers.txt', '3-servers.txt', '4-servers.txt',  '5-servers.txt']

    all_probs = []
    for stats_file in onlyfiles:
        print(stats_file)

        with open(directory_with_stats+stats_file, "r") as file:
            lines = file.readlines()

        lines = lines[2:]  # exclude experiments details
        for i in range(len(lines)):
            lines[i] = lines[i].strip("\n")  # strip new line characters

        probs = []
        no_combos = []
        for i in range(len(lines)):
            tmp = lines[i].split(" ")
            no_combos.append(int(tmp[0]))
            probs.append(float(tmp[1]))

        probs = np.array(probs)

        all_probs.append(probs)
        no_combos = np.array(no_combos)

    fig, ax = plt.subplots()
    ax.autoscale_view()

    x_points = [5 for i in range(len(onlyfiles))]  # reference points to the probability of having 20 common combos
    y_points = [all_probs[i][4] for i in range(len(onlyfiles))]
    plt.vlines(x_points, 0, y_points, linestyle="dotted", colors='k')
    plt.hlines(y_points, 0, x_points, linestyle="dotted", colors='k')

    for i in range(len(onlyfiles)):
        print(i)
        print(all_probs[i][4])

    x_points_1=[]
    y_points_1=[]
    x_points_1.append(5)
    x_points_1.append(10)
    x_points_1.append(20)
    y_points_1.append(0.967)
    y_points_1.append(0.847)
    y_points_1.append(0.342)

    plt.vlines(x_points_1, 0, y_points_1, linestyle="dotted", colors='k')
    plt.hlines(y_points_1, 0, x_points_1, linestyle="dotted", colors='k')

    plt.xticks(np.append(no_combos[::19],(2,4,5,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34)),np.append(no_combos[::19],(2,4,5,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34)))
    y_labels = [0.1, 0.2, 0.3, 0.4, 0.5, 0.7, 0.8, 1.0, 0.967, 0.967, 0.847, 0.847,  0.459, 0.459, 0.015, 0.015, 0.342, 0.342, 0.6, 0.9]
    y_labels_t = ['0.1', '0.2', '0.3', '0.4', '0.5','0.7','0.8', '1.0', '0.96', '0.96', '0.85', '0.85', '0.46', '0.46', '0.015', '0.015', '0.34','0.34', '0.6', '0.9']
    plt.yticks(y_labels,y_labels_t)

    plt.xlim([1, 35])
    plt.ylim([0, 1.02])

    # plot experimental results
    for i in range(len(all_probs)):
        plt.plot(no_combos, all_probs[i], "--", markerfacecolor='None', label=onlyfiles[i].strip(".txt"))

    plt.ylabel("Probability")
    plt.xlabel("No. of common CTs")
    plt.legend(loc="upper right", prop={'size': 10}, frameon=False)

    plt.show()


# EXECUTE PROGRAM
if __name__ == '__main__':

    window_size='0'
    while window_size not in ['40','80']:
        window_size = input("Give no. of CTs per user (either 40 or 80):")

    window_size = int(window_size)


    # create the directory hosting the probabilities/statistics
    if not os.path.exists("probs_common_combos_exps/"):
        os.makedirs("probs_common_combos_exps/")
    if not os.path.exists("probs_common_combos_exps/Bernoulli(" + str(p) + ")/"):
        os.makedirs("probs_common_combos_exps/Bernoulli(" + str(p) + ")/")
    if not os.path.exists("probs_common_combos_exps/Bernoulli(" + str(p) + ")/"+str(window_size)+"/"):
        os.makedirs("probs_common_combos_exps/Bernoulli(" + str(p) + ")/"+str(window_size)+"/")

    print("Producing stats...")
    no_servers_breached = [i for i in range(2,6)]  # no. of servers to consider breached per experiment

    for i in no_servers_breached:
        at_least_common_combos(i,window_size,p)  # execute experiment with i servers breached

    # plot graph
    if window_size==40:
        multiple_servers_graph_0(p,window_size)
    elif window_size==80:
        multiple_servers_graph_1(p,window_size)

    print("The collected statistics are stored in folder probs_common_combos_exps/")




