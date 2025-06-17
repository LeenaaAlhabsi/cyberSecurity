import itertools
import string
import time 

def main():
    # Prompt the user for their "secret" 7-character password (5 lowercase + 2 digits)
    secret = input("Enter a 7-character password (5 lowercase letters + 2 digits): ").strip()
    if len(secret) != 7 or not (secret[:5].islower() and secret[5:].isdigit()):
        print("Password must be exactly 7 characters: 5 lowercase letters followed by 2 digits.")
        return

    print("\nStarting brute-force…\n")

    # Initialize the guess to the first possible combination
    guess = "aaaaa00"
    time_start = time.time()  # Start the timer
    attempts = 0

    while guess != secret:
        # Print the current guess
        print(f"Trying: {guess} ")

        # Increment the guess to the next combination
        attempts, guess = increment_guess(guess, attempts)

    time_end = time.time()  # End the timer
    elapsed_time = time_end - time_start  # Calculate elapsed time

    print(f"\nPassword found: {secret!r} in {attempts} attempts.")
    print(f"Time taken: {elapsed_time:.2f} seconds.")

def increment_guess(guess, attempts):
    """
    Increment the guess string as if it were a base-36 number (26 letters + 10 digits).
    'aaaaa00' -> 'aaaaa01', ..., 'aaaaa99' -> 'aaaab00', ..., 'zzzzz99'
    """
    chars = string.ascii_lowercase + string.digits  # Lowercase letters and digits
    guess_list = list(guess)  # Convert the guess to a list for mutability

    # Start from the last character and increment
    for i in range(len(guess_list) - 1, -1, -1):
        if guess_list[i] != chars[-1]:  # If not the last character in chars
            guess_list[i] = chars[chars.index(guess_list[i]) + 1]  # Increment the character
            break
        else:  # If the character is the last in chars, reset it to the first character
            guess_list[i] = chars[0]
    else:
        # If all characters are at their maximum value, return None (no more combinations)
        return attempts, None

    attempts += 1
    return attempts, ''.join(guess_list)

if __name__ == "__main__":
    main()