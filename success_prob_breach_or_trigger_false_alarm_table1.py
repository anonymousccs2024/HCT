"""
Calculates the success rate of online depth- and breadth-first adversaries in either breaching a target account (i.e.,
triggering its valid CT) or causing a false breach alarm (i.e., triggering decoy CTs). Stats shown in Table 1.
"""

def guessing_campaign(total_combos,depth_or_breadth,decoys):
    """
    Calculates the theoretical probability of a depth- or breadth-first attack on compromising an account or raising a
    false breach alarm denoted by ON(login_attempts_per_user,no_of_target_users). For depth-first attacks ON(10^6,10),
    whereas for breadth-first attacks ON(10^4,1000). Lower than 0.1, match Wang et al. (Bernoulli paper) thresholds.
    :param total_combos: The total token combinations
    :param depth_or_breadth: 0 for depth-first attack; 1 for breadth-first attack
    :param decoys: the decoy tokens (excluding the real password)
    :return: Nothing. It prints the results on the screen.
    """
    print("\tResults with total no. of tokens/combos: ", total_combos)
    if depth_or_breadth == 0:
        if decoys == 39:
            no_of_allowed_guesses = pow(10,6)
        elif decoys == 79:
            no_of_allowed_guesses = pow(10, 5)
    elif depth_or_breadth == 1:
        if decoys == 39:
            no_of_allowed_guesses = pow(10,4)
        elif decoys == 79:
            no_of_allowed_guesses = pow(10, 3)
    else:
        print("Wrong option!")
        exit(0)

    prob_not_raising_alarm = 1
    # first, calc probability of not triggering any of either the decoys or the valid combo for all login attempts
    for i in range(no_of_allowed_guesses):
        prob_not_raising_alarm*=((total_combos-(decoys+1)-i)/(total_combos-i))
    #print("\tP(a): ",abs(prob_not_raising_alarm))

    # second, calc probability of selecting the valid combo at any point in the guessing campaign
    prob_guess_valid_combo = 0
    prev = 1
    for i in range(no_of_allowed_guesses):
        prob_guess_valid_combo += prev * (1/(total_combos-i))
        prev*=(total_combos-(decoys+1)-i)/(total_combos-i)

    mul = 1
    if depth_or_breadth == 0:
        no_target_accounts = 10
    else:
        no_target_accounts = 1000
    for i in range(no_target_accounts):
        mul *= (1 - prob_guess_valid_combo)
    #print("Π1-10(1-P(b)) = ", mul)
    if depth_or_breadth == 0:
        print("\tON(10^6,10) -- breaching a target account = ", 1 - mul)
    else:
        print("\tON(10^4,1000) -- breaching a target account = ", 1 - mul)

    mul = 1
    for i in range(no_target_accounts):
        mul *= (prob_not_raising_alarm+prob_guess_valid_combo)
    #print("ON(10^6,10)^c = Π1-10(ON(10^6,1)^c) = ",mul)
    if depth_or_breadth == 0:
        print("\tON(10^6,10) -- causing a false breach alarm = 1 - ON(10^6,10)^c = ", 1-mul)
    else:
        print("\tON(10^4,1000) -- causing a false breach alarm = 1 - ON(10^4,1000)^c = ", 1 - mul)
    print()


# execute program
if __name__ == '__main__':

    window_size = '0'
    while window_size not in ['40', '80']:
        window_size = input("Give no. of CTs per user (either 40 or 80):")

    total_combos_options = []
    decoys = int(window_size) - 1
    if decoys == 39:
        total_combos_options = [pow(10,6),  pow(10,7),  pow(10,8), pow(10,9), int(3 * pow(10,9)), int(3.73 * pow(10,9))]
    elif decoys == 79:
        total_combos_options = [int(7.55 * pow(10, 8))]  # ,int(8 * pow(10,9))]

    print("Depth first attacks...")
    for total_combos in total_combos_options:
        guessing_campaign(total_combos,0,decoys)
    print("Depth first attacks... [COMPLETED]")
    print()
    print("Breadth first attacks...")
    for total_combos in total_combos_options:
        guessing_campaign(total_combos,1,decoys)
    print("Breadth first attacks... [COMPLETED]")




