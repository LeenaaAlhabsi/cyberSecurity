import itertools
import time

def main():
    # Array of words to use for combinations
    words = [
        "Sara", "Dammam", "nutritionist", "2016", "Faisal", "5", "Rayan", 
        "Majid", "AlMohandis", "Hyundai", "Tucson", "2020", "sara.fitness"
    ]

    # Prompt the user for their "secret" password
    secret = input("Enter your password (combination of words from the array): ").strip()
    print("\nStarting brute-force…\n")

    time_start = time.time()  # Start the timer
    attempts = 0

    # Try combinations of words from the array
    for r in range(1, len(words) + 1):  # Try combinations of 1 word up to all words
        for combination in itertools.permutations(words, r):  # Generate permutations
            attempts += 1
            guess = ''.join(combination)  # Combine words into a single string
            print(f"Trying: {guess}")

            if guess == secret:  # Check if the guess matches the secret
                time_end = time.time()  # End the timer
                elapsed_time = time_end - time_start  # Calculate elapsed time
                print(f"\nPassword found: {secret!r} in {attempts} attempts.")
                print(f"Time taken: {elapsed_time:.2f} seconds.")
                return

    print("\nPassword not found in the given word combinations.")

if __name__ == "__main__":
    main()