import itertools
import argparse
import sys
import os


def print_banner():
    """Prints a welcome banner."""
    banner = """
█░█░█ █▀█ █▀█ █▀▄ █░░ █ █▀ ▀█▀   █▀▀ █▀▀ █▄░█ █▀▀ █▀█ ▄▀█ ▀█▀ █▀█ █▀█
▀▄▀▄▀ █▄█ █▀▄ █▄▀ █▄▄ █ ▄█ ░█░   █▄█ ██▄ █░▀█ ██▄ █▀▄ █▀█ ░█░ █▄█ █▀▄
        Custom Wordlist Generator V1.0
---------------------------------------------------
    """
    print(banner)

def generate_wordlist(min_len, max_len, char_set, output_file):
    """
    Generates a wordlist based on specified parameters and writes it to a file.
    """
    total_combinations = 0
    # Calculate total combinations to estimate progress
    for length in range(min_len, max_len + 1):
        total_combinations += len(char_set) ** length

    print(f"[+] Starting wordlist generation...")
    print(f"[+] Minimum length: {min_len}")
    print(f"[+] Maximum length: {max_len}")
    print(f"[+] Character set size: {len(char_set)}")
    # Estimate file size
    estimated_size_mb = (total_combinations * (max_len + 1) / (1024 * 1024))
    print(f"[!] Estimated number of combinations: {total_combinations:,}")
    print(f"[!] Estimated file size (MB, rough): {estimated_size_mb:.2f} (can be very large!)")
    print(f"[!] Writing to: {output_file}")
    
    generated_count = 0
    start_time = time.time()

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for length in range(min_len, max_len + 1):
                print(f"[*] Generating combinations for length {length}...", end='\r')
                for combination in itertools.product(char_set, repeat=length):
                    word = "".join(combination)
                    f.write(word + '\n')
                    generated_count += 1
                    if generated_count % 100000 == 0: # Update progress every 100,000 words
                        elapsed_time = time.time() - start_time
                        words_per_sec = generated_count / elapsed_time if elapsed_time > 0 else 0
                        sys.stdout.write(f"\r[*] Generated: {generated_count:,} words | Current length: {length} | {words_per_sec:.2f} words/sec | Elapsed: {int(elapsed_time)}s")
                        sys.stdout.flush()

        elapsed_time = time.time() - start_time
        print(f"\n[+] Wordlist generation complete!")
        print(f"[+] Total words generated: {generated_count:,}")
        print(f"[+] Time taken: {elapsed_time:.2f} seconds")
    except IOError as e:
        print(f"[-] Error writing to file '{output_file}': {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Custom Wordlist Generator tool.")
    parser.add_argument("-min", "--min_length", type=int, default=1, help="Minimum length of passwords to generate.")
    parser.add_argument("-max", "--max_length", type=int, default=8, help="Maximum length of passwords to generate.")
    parser.add_argument("-o", "--output", default="custom_wordlist.txt", help="Output file name for the wordlist.")
    parser.add_argument("-l", "--lowercase", action="store_true", help="Include lowercase characters (a-z).")
    parser.add_argument("-u", "--uppercase", action="store_true", help="Include uppercase characters (A-Z).")
    parser.add_argument("-d", "--digits", action="store_true", help="Include digits (0-9).")
    parser.add_argument("-s", "--symbols", action="store_true", help="Include common symbols (!@#$%^&*()).")
    parser.add_argument("-a", "--all_chars", action="store_true", help="Include all common character types (lowercase, uppercase, digits, symbols).")
    parser.add_argument("-c", "--custom_charset", type=str, help="Specify a custom character set (e.g., 'abc123!@#'). Overrides -l, -u, -d, -s, -a.")

    args = parser.parse_args()

    # Define character sets
    lowercase_chars = "abcdefghijklmnopqrstuvwxyz"
    uppercase_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digit_chars = "0123456789"
    symbol_chars = "!@#$%^&*()-_+=[]{}<>,.?/\\|`~" # Removed single and double quotes to avoid issues with some systems

    selected_char_set = ""

    if args.custom_charset:
        selected_char_set = args.custom_charset
    elif args.all_chars:
        selected_char_set = lowercase_chars + uppercase_chars + digit_chars + symbol_chars
    else:
        if args.lowercase:
            selected_char_set += lowercase_chars
        if args.uppercase:
            selected_char_set += uppercase_chars
        if args.digits:
            selected_char_set += digit_chars
        if args.symbols:
            selected_char_set += symbol_chars
    
    if not selected_char_set:
        print("[-] Error: You must select at least one character type (e.g., -l, -u, -d, -s, -a) or provide a custom character set (-c).")
        parser.print_help()
        sys.exit(1)

    if args.min_length > args.max_length:
        print("[-] Error: Minimum length cannot be greater than maximum length.")
        sys.exit(1)

    # Convert selected_char_set to a string for itertools.product
    char_set_str = "".join(sorted(list(set(selected_char_set)))) # Remove duplicates and sort for consistency

    if not char_set_str:
        print("[-] Error: The selected character set is empty after processing.")
        sys.exit(1)

    print(f"[+] Effective character set: '{char_set_str}' (Length: {len(char_set_str)})")
    
    generate_wordlist(args.min_length, args.max_length, char_set_str, args.output)

