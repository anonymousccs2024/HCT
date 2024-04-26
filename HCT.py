"""Prototype implementation of HCT framework. When executed, allows user to register, authenticate and exit."""

import os
import random
import pandas as pd
import numpy as np
from colorama import Fore, init
init(autoreset=True)
from Crypto.Hash import SHA3_256

MOD = 256  # RC4 produces single bytes

success_prob = 0.3  # Success probability of selecting a CT as decoy following a Bernoulli dist.

def KSA(key):
    ''' Key Scheduling Algorithm (from wikipedia):
        for i from 0 to 255
            S[i] := i
        endfor
        j := 0
        for i from 0 to 255
            j := (j + S[i] + key[i mod keylength]) mod 256
            swap values of S[i] and S[j]
        endfor
    '''
    key_length = len(key)
    # create the array "S"
    S = list(range(MOD))  # [0,1,2, ... , 255]
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]  # swap values

    return S


def PRGA(S,no_of_random_ints):
    ''' Psudo Random Generation Algorithm (from wikipedia):
        i := 0
        j := 0
        while GeneratingOutput:
            i := (i + 1) mod 256
            j := (j + S[i]) mod 256
            swap values of S[i] and S[j]
            K := S[(S[i] + S[j]) mod 256]
            output K
        endwhile
    '''
    i = 0
    j = 0
    for z in range(no_of_random_ints):
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD

        S[i], S[j] = S[j], S[i]  # swap values
        K = S[(S[i] + S[j]) % MOD]
        yield K


def get_keystream(key,no_of_random_ints):
    ''' Takes the encryption key to get the keystream using PRGA
        return object is a generator
    '''
    S = KSA(key)
    return PRGA(S,no_of_random_ints)


def compute_sha3_256_hash(input_string):
    # Convert the input string to bytes
    input_bytes = input_string.encode('utf-8')

    # Create a SHA3_256 hash object
    sha3_256_hash = SHA3_256.new()

    # Update the hash object with the input bytes
    sha3_256_hash.update(input_bytes)

    # Get the hexadecimal representation of the hash
    hex_digest = sha3_256_hash.hexdigest()

    return hex_digest


def generate_random_integer(real_password_sha3_256_hash, low, high):
    """
    Returns a random integer within range [low,high] using RC4 algorithm.
    :param real_password_sha3_256_hash: the user-chosen password (sha3-256) digest in bytes format
    :param low: min CT
    :param high: max CT
    :return: the CT corresponding to the given sha3-256 digest
    """
    no_of_random_ints = 4  # 4 bytes to cover 3.73x10^9 CT combos
    keystream = get_keystream(real_password_sha3_256_hash, no_of_random_ints)
    CT = []
    for i in keystream:
        CT.append(i)
    CT = bytes(CT)
    integer_value = int.from_bytes(CT, byteorder='big')
    integer_value = low + (integer_value % (high - low + 1))  # Scale integer to fit within range

    return integer_value


def calc_lists_of_tokens(valid_combo,window_size,total_cts):
    """
    This function creates a sweet-CT list by taking the neighbouring integers around the valid CT and selecting them
    as either a decoy, following a Bernoulli process with p=0.3, or a meta-decoy with 1-p.
    :param valid_combo: The valid CT
    :param window_size: The window size
    :return: A list with window_size CTs
    """
    # calculate the 20-element sweet-CT list
    rows = []
    l_win = random.randint(0, window_size - 1)  # calc left window
    r_win = window_size - l_win - 1  # calc right window=
    if l_win + r_win + 1 != window_size:
        print("Error on calculating windows!!!")
        exit(0)
    #print("Left window: " + str(l_win))
    #print("Right window: " + str(r_win))
    tmp_row = []
    i = 1
    # first the left window
    while l_win > 0:
        include_flag = np.random.binomial(1, success_prob, 1)[0]  # first argument coverts binomial to bernoulli dist.
        if include_flag == 1:
            tmp_tok = valid_combo - i
            if tmp_tok < 0:  # if it goes  lower than 0 just start from the upper bound.
                tmp_tok = total_cts - abs(tmp_tok)
            tmp_row.append(tmp_tok)
            l_win-=1
        i+=1

    # add the valid token
    tmp_row.append(valid_combo)

    i = 1
    # then the right window
    while r_win > 0:
        include_flag = np.random.binomial(1, success_prob, 1)[0]  # first argument coverts binomial to bernoulli dist.
        if include_flag == 1:
            tmp_tok = valid_combo + i
            if tmp_tok >= total_cts:  # if it goes upper than 255 just start from the lower bound
                tmp_tok -= total_cts
            tmp_row.append(tmp_tok)  # append token to the list
            r_win -= 1
        i+=1

    tmp_row.sort()
    #print("Valid CT:",valid_combo)
    #print("CT list:",tmp_row)
    rows.append(tmp_row)

    return rows

def registration_phase(user_id,real_password,print_info_flag,total_cts,server_i,window_size):
    """
    Represents the registration phase in HCT framework.
    :param user_id: The user's id
    :param real_password: The user-chosen password in plain-text format
    :param print_info_flag: flag to print intermediate steps (1) or not (0)
    :param total_cts: The total no. of CT combos
    :param server_i: An integer identifier of the server
    :param window_size: The no. of CTs per user
    :return: None
    """

    # create the directory hosting the authentication server S's passwords files (if not exists)
    if not os.path.exists("authentication_server_S/"):
        os.makedirs("authentication_server_S/")

    # first, check whether a user with the same user_id already exists in the system
    if os.path.exists('authentication_server_S/password_file_F.txt'):
        usernames = pd.read_csv('authentication_server_S/password_file_F.txt', delim_whitespace=True, header=None)
        usernames = (usernames.iloc[:, 0]).tolist()
        for username in usernames:
            if username == user_id:
                if print_info_flag == 1:
                    print("A registered user with the same username already exists in the system! Please, rovide a different username.")
                return 1

    # produce the valid CT for the given password
    real_password_sha3_256_hash = compute_sha3_256_hash(real_password)  # get sha3-256 digest of the give password
    #print("SHA3-256 hash:", real_password_sha3_256_hash)

    valid_combo = generate_random_integer(real_password_sha3_256_hash.encode('utf-8'), 0, total_cts-1) # get valid CT

    # generate the sweet-CT list with window_size CTs in total, 1 of them valid the rest decoys
    random.seed()
    sweet_ct_list = calc_lists_of_tokens(valid_combo,window_size,total_cts)[0]

    if print_info_flag == 1:
        print()
        print("The user's valid CT: "+str(valid_combo))
        print("The user's sweet-CT list:",sweet_ct_list)

    # save user's sweet-CT list in password file F, along the user ID, the no. of meta-decoys triggered, and a 'Locked' or active (-) flag
    with open("authentication_server_S/password_file_F_"+str(server_i)+".txt","a") as file:
        file.write(str(user_id))
        file.write(" ")
        file.write(str(0))  # no. of meta-decoys triggered
        file.write(" - ")  # - if the account is active, "Locked" if the account is locked
        for i in sweet_ct_list:
            file.write(str(i))
            file.write(" ")
        file.write("\n")

    # calculate the index of the valid CT in the sweet-CT list
    idx_to_valid_combo = sweet_ct_list.index(valid_combo)
    if print_info_flag == 1:
        print("Index of valid CT:",idx_to_valid_combo)

    # create the directory hosting the honeychecker's sensitive files (if not exists)
    if not os.path.exists("Honeychecker/"):
        os.makedirs("Honeychecker/")

    # create a record in the honeychecker's file with the user_id, the index of the valid CT in the user's sweet-CT list, and a decoy counter per user (initially set to 0)
    with open("Honeychecker/valid_idx_per_user_"+str(server_i)+".txt", "a") as file:
        file.write(str(user_id))
        file.write(" ")
        file.write(str(idx_to_valid_combo))
        file.write(" ")
        file.write(str(0))
        file.write("\n")

    if print_info_flag == 1:
        print()
        print(Fore.GREEN + "User "+str(user_id)+" registered successfully!")
        #print("User "+str(user_id)+" registered successfully!")
        print()


def invoke_honeyckecker(user_id,triggered_index,print_info_flag,server_i,decoy_ct_threshold):
    """
    Invoke the honeychecker with tje index of the triggered CT in the sweet-CT list to verify login attempt. If a
    decoy is triggered, the honeychecker increases a counter for that user. If that counter surpasses the
    decoy_ct_threshold a breach alarm is signalled.
    :param user_id: The user's id
    :param triggered_index: The index of the triggered CT in the user's sweet-CT list
    :param print_info_flag: flag to print intermediate steps (1) or not (0)
    :param server_i: An integer identifier of the server
    :param decoy_ct_threshold: The no. of decoys per user that if triggered alert a breach alarm for the whole system
    :return: None
    """

    # read all users' valid combos
    valid_combos = pd.read_csv('Honeychecker/valid_idx_per_user_'+str(server_i)+'.txt',delim_whitespace=True,header=None)
    usernames = (valid_combos.iloc[:, 0]).tolist()  # extract usernames from the dataframe for all users
    decoy_ct_counters = (valid_combos.iloc[:,2]).tolist()  # extract the counters for decoy CT triggers
    valid_combos = (valid_combos.iloc[:,1]).tolist()  # extract indexes of the valid CT for each user

    # get the index of the user's valid CT stored at the honeychecker
    valid_ct_index = -1
    for user in range(len(usernames)):
        if usernames[user] == user_id:
            valid_ct_index = valid_combos[user]
            break

    if valid_ct_index == -1:
        print("User's valid combos not in the honeychecker!")
        exit(0)

    # check if the triggered CT's index in sweet-CT list is the same as the one stored at the honeychecker
    if print_info_flag == 1:
        print("Index of valid CT:", valid_ct_index)
        print("Triggered index:", triggered_index)
        print()

    if triggered_index != valid_ct_index:
        decoy_ct_counters[user]+=1 # increase the no. of triggered decoys for that user by 1
        # sound alarm if the decoy_ct_threshold is surpassed
        if decoy_ct_counters[user] == decoy_ct_threshold:
            return 1
    else:
        # approve the login attempt
        return 0

    # update the honeychecker's file
    with open("Honeychecker/valid_idx_per_user_" + str(server_i) + ".txt", "w") as file:
        for i in range(len(usernames)):
            file.write(str(usernames[i]))
            file.write(" ")
            file.write(str(valid_combos[i]))
            file.write(" ")
            file.write(str(decoy_ct_counters[i])) # No of times a decoy is triggered
            file.write("\n")
    return 2

def authentication_phase(user_id,password,total_cts,print_info_flag,server_i,meta_decoy_threshold,decoy_ct_threshold):
    """
    This function represents the authentication phase in HCT framework.
    :param user_id: The user's id
    :param password: Their plain-text password
    :param total_cts: The total no. of CT combos
    :param print_info_flag: flag to print intermediate steps (1) or not (0)
    :param server_i: An integer identifier of the server
    :param meta_decoy_threshold: Meta-decoys threshold that if surpassed the system takes action
    :param decoy_ct_threshold: The no. of decoys per user that if triggered alert a breach alarm for the whole system
    :return: None
    """

    # read the password file F
    combos = pd.read_csv('authentication_server_S/password_file_F_'+str(server_i)+'.txt',delim_whitespace=True,header=None)
    usernames = (combos.iloc[:,0]).tolist()  # extract usernames

    # check the user is registered to the sytem
    user_found_flag=0
    for username in usernames:
        if username == user_id:
            # user found
            user_found_flag=1
            break
    if user_found_flag==0:
        # no user with the given user_id is registered in the system
        print("A user with username " + str(user_id) + " does not exist in the system!")
        exit(0)

    meta_decoy_counter = (combos.iloc[:,1]).tolist()  # extract the meta-decoy counters for all users

    locked_accounts = (combos.iloc[:,2]).tolist()  # extract (un)lock identifiers for all users

    combos = combos.iloc[:,3:]  # extract the users' sweet-CT lists

    meta_decoy_triggered_flag=0
    # find the user's sweet-CT list
    for i in range(len(usernames)):
        if usernames[i] == user_id:
            if locked_accounts[i] == 'Locked':
                print(Fore.RED + "This account has been locked for suspicious behaviour!")
                print()
                break

            sweet_ct_list = combos.iloc[i,:]
            sweet_ct_list = np.array(sweet_ct_list.tolist())
            sweet_ct_list = list(map(int, sweet_ct_list[:]))
            #print(sweet_ct_list)

            # calculate the CT for the given password
            real_password_sha3_256_hash = compute_sha3_256_hash(password)  # get the sha3-256 digest for password
            # print("SHA3-256 hash:", real_password_sha3_256_hash)
            valid_combo = generate_random_integer(real_password_sha3_256_hash.encode('utf-8'), 0, total_cts - 1)

            if print_info_flag == 1:
                print()
                print("The triggered CT: " + str(valid_combo))
                print("The user's sweet-CT list:", sweet_ct_list)

            # get the index of the yielded CT in the retrieved user's sweet-CT list
            if valid_combo not in sweet_ct_list:
                # the given password does not map to any possible combo for that particular user
                print(Fore.RED + "Wrong password given! (Decline access to the system).")
                if valid_combo>=sweet_ct_list[0] and valid_combo<=sweet_ct_list[-1]:
                    meta_decoy_counter[i]+=1
                    if meta_decoy_counter[i]==meta_decoy_threshold:
                        # meta-decoy threshold reached --take action. In this case, we just lock the account.
                        locked_accounts[i] = 'Locked'
                    meta_decoy_triggered_flag = 1
                break
            else:
                # get the index of the triggered CT in the user's sweet-CT list
                triggered_index = int(sweet_ct_list.index(valid_combo))

            # if the execution continues, it means that the given password triggered a CT in the user's sweet-CT list
            # invoke the honeychecker to verify the login attempt (check the given index)
            response = invoke_honeyckecker(user_id,triggered_index,print_info_flag,server_i,decoy_ct_threshold)

            if response == 1:
                # 1 = sound an alarm
                print(Fore.RED + 'SOUND ALARM!!! A data-breach has been detected!!!')
            elif response == 0:
                # 0 = approve login attempt
                print(Fore.GREEN + "ACCESS GRANTED! (the login attempt triggered the valid combo --the one stored at the honeychecker)")
            elif response == 2:
                # 2 = decoy CT triggered but threshold not reached yet. Normal login failed message will be shown
                print(Fore.RED + "Wrong password given! (Decline access to the system). Decoy CT triggered but alarm threshold was not reached.")
            break

    # if meta_decoy triggered rewrite the password file F with the new counter
    if meta_decoy_triggered_flag == 1:
        with open("authentication_server_S/password_file_F_"+str(server_i)+".txt","w") as file:
            for i in range(len(usernames)):
                file.write(usernames[i])
                file.write(" ")
                file.write(str(meta_decoy_counter[i]))
                file.write(" ")
                file.write(locked_accounts[i])
                file.write(" ")
                sweet_ct_list = combos.iloc[i, :]
                sweet_ct_list = np.array(sweet_ct_list.tolist())
                sweet_ct_list = list(map(int, sweet_ct_list[:]))
                for j in sweet_ct_list:
                    file.write(str(j))
                    file.write(" ")
                file.write("\n")

def start_hct():

    total_cts = int(3.73 * pow(10,9))  # the total no. of CT combinations

    option = -1

    server_i = 0  # server identifier -- to be used for intersection experiments

    meta_decoy_threshold = 1  # threshold of meta-decoys triggered to take action
    decoy_ct_threshold = 2  # threshold of decoys triggered to raise a breach alarm

    window_size = 40  # total CTs per user

    print("Welcome to the prototype of HCT.")

    while option != 3:
        print("Main menu:")
        print("==========")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        option = input("Enter the no. of the action you want to execute (provide only an integer 1-3): ")
        # perform some input checks
        try:
            option = int(option)
        except:
            print(Fore.RED + "Non-integer input given!")
            continue
        if option < 1 or option > 3:
            print(Fore.RED + "Out-of-bounds integer given!")
            continue

        if option == 3:
            print()
            print("Exit selected. Thanks for using HCT! :)")
            exit(0)
        elif option == 1:
            user_id = input("Register selected. Please provide the username: ")
            password = input("Please provide password: ")
            registration_phase(user_id, password,1,total_cts,server_i,window_size)
        elif option == 2:
            user_id = input("Login selected. Please provide the username: ")
            password = input("Please provide password: ")
            authentication_phase(user_id, password,total_cts,1,server_i,meta_decoy_threshold,decoy_ct_threshold)


# START HCT FRAMEWORK
if __name__ == '__main__':
    start_hct()
