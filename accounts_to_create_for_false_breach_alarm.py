"""
Calculates the average no. of accounts that an online guessing adversary who knows the real password must create in
order for one of them to trigger only decoys, without any meta-decoy, surpass the decoys' threshold, and induce a
false breach alarm.
"""
import random
import numpy as np
from HCT import compute_sha3_256_hash, generate_random_integer,calc_lists_of_tokens

def create_accounts():

    real_password = "test1234"
    total_cts = int(3.73 * pow(10,9))
    window_size = 40
    decoys_threshold = 2
    no_created_accounts = []

    no_experiments = 1000
    seed = 0
    for j in range(no_experiments):

        if j % 100 == 0:
            print("Experiment",j)
        no_created_accountstmp = 0

        while True:
            #print("Accounts created so far",no_created_accountstmp)

            # produce the valid k-token combo for the given password
            real_password_sha3_256_hash = compute_sha3_256_hash(real_password)
            # print("SHA3-256 hash:", real_password_sha3_256_hash)
            valid_combo = generate_random_integer(real_password_sha3_256_hash.encode('utf-8'), 0, total_cts - 1)
            # create the sweet-CT list for user containing 20 CTs in total, 1 valid and 19 decoys adjacent to the valid CT
            random.seed(seed)
            sweet_ct_list = calc_lists_of_tokens(valid_combo, window_size, total_cts)[0]

            # conduct the attack to raise a false alarn
            left_right = 0  # left 0, right 1
            counter_i = 1
            found_decoys = 0

            np.random.seed(seed)
            seed+=1

            alarm_flag = 0
            while True:
                if found_decoys == decoys_threshold:
                    alarm_flag = 1
                    break

                include_flag = np.random.binomial(1, 0.3, 1)[0]  # select it as decoy with 0.2 prob

                if include_flag == 1:
                    if left_right == 0:
                        if (valid_combo - counter_i) in sweet_ct_list:
                            found_decoys += 1
                            left_right = 1
                            continue
                        break
                    elif left_right == 1:
                        if (valid_combo + counter_i) in sweet_ct_list:
                            found_decoys += 1
                            left_right = 0
                            counter_i += 1
                            continue
                        break
                else:
                    if left_right == 0:
                        left_right = 1
                    elif left_right == 1:
                        counter_i += 1
                        left_right = 0

            if alarm_flag ==1:
                # the decoys threshold was suproseed so an alarm occured
                no_created_accounts.append(no_created_accountstmp)
                break
            else:
                # booby trap was issued so it is a failed experiment, create a new account
                no_created_accountstmp+=1
                continue

    print("Average no. of accounts created for signaling an alarm after performing experiment for",str(no_experiments)," times is:",round(np.mean(no_created_accounts)))

if __name__ == '__main__':
    create_accounts()