#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "cmdhfmfhard.h"
#include "crapto1.h"
#include "parity.h"

typedef enum {
    KEY_A,
    KEY_B
} key_type_t;

// Function prototypes
int process_nonces(FILE *fp, uint32_t uid, uint8_t sector, key_type_t key_type, FILE *output_fp);
int write_nonces_to_temp_file(FILE *fp, FILE *temp_fp, uint32_t current_uid, uint8_t current_sector, key_type_t current_key_type);

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 4) {
        printf("Usage: %s <nonce_file_path> [-o <output_file>]\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    FILE *output_fp = NULL;
    if (argc == 4 && (strcmp(argv[2], "-o") == 0 || strcmp(argv[2], "--output") == 0)) {
        output_fp = fopen(argv[3], "w");
        if (output_fp == NULL) {
            perror("Error opening output file");
            fclose(fp);
            return 1;
        }
    }

    uint32_t current_uid = 0;
    uint8_t current_sector = 0;
    key_type_t current_key_type = KEY_A;
    char line[256];
    long file_position = 0;

    while (1) {
        file_position = ftell(fp);
        if (fgets(line, sizeof(line), fp) == NULL) {
            break;  // End of file
        }

        // Skip lines containing "dist"
        if (strstr(line, "dist") != NULL) {
            continue;
        }

        uint32_t uid;
        uint8_t sector;
        char key_type_str[2];

        if (sscanf(line, "Sec %hhu key %1s cuid %x", &sector, key_type_str, &uid) == 3) {
            key_type_t key_type = (key_type_str[0] == 'A') ? KEY_A : KEY_B;

            if (uid != current_uid || sector != current_sector || key_type != current_key_type) {
                if (current_uid != 0) {
                    fseek(fp, 0, SEEK_SET);  // Seek to the beginning of the file
                    process_nonces(fp, current_uid, current_sector, current_key_type, output_fp);
                    fseek(fp, file_position, SEEK_SET);  // Return to the current position
                }
                current_uid = uid;
                current_sector = sector;
                current_key_type = key_type;
            }
        }
    }

    if (current_uid != 0) {
        fseek(fp, 0, SEEK_SET);  // Seek to the beginning of the file
        process_nonces(fp, current_uid, current_sector, current_key_type, output_fp);
    }

    fclose(fp);
    if (output_fp != NULL) {
        fclose(output_fp);
    }
    return 0;
}

int process_nonces(FILE *fp, uint32_t uid, uint8_t sector, key_type_t key_type, FILE *output_fp) {
    char temp_file[] = "temp_nonces.txt";
    FILE *temp_fp = fopen(temp_file, "w");
    if (temp_fp == NULL) {
        perror("Error creating temporary file");
        return 1;
    }

    if (write_nonces_to_temp_file(fp, temp_fp, uid, sector, key_type) != 0) {
        fclose(temp_fp);
        remove(temp_file);
        return 1;
    }

    fclose(temp_fp);

    uint64_t foundkey = 0;
    int result = mfnestedhard(0, key_type, NULL, 0, 0, NULL, false, false, false, &foundkey, NULL, uid, temp_file);

    if (result == 1) {
        printf("Key found for UID: %08x, Sector: %d, Key type: %c: %012" PRIx64 "\n",
               uid, sector, (key_type == KEY_A) ? 'A' : 'B', foundkey);
        if (output_fp != NULL) {
            fprintf(output_fp, "Key found for UID: %08x, Sector: %d, Key type: %c: %012" PRIx64 "\n",
                    uid, sector, (key_type == KEY_A) ? 'A' : 'B', foundkey);
            fflush(output_fp); // Fuerza la escritura inmediata en el archivo
        }
    } else {
        printf("Key not found for UID: %08x, Sector: %d, Key type: %c\n",
               uid, sector, (key_type == KEY_A) ? 'A' : 'B');
    }

    remove(temp_file);
    return 0;
}

int write_nonces_to_temp_file(FILE *fp, FILE *temp_fp, uint32_t current_uid, uint8_t current_sector, key_type_t current_key_type) {
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Skip lines containing "dist"
        if (strstr(line, "dist") != NULL) {
            continue;
        }

        uint32_t line_uid;
        uint8_t line_sector;
        char line_key_type_str[2];

        if (sscanf(line, "Sec %hhu key %1s cuid %x", &line_sector, line_key_type_str, &line_uid) == 3) {
            key_type_t line_key_type = (line_key_type_str[0] == 'A') ? KEY_A : KEY_B;
            if (line_uid == current_uid && line_sector == current_sector && line_key_type == current_key_type) {
                char ks0_str[9], par0_str[5];
                if (sscanf(line, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %8s %*s %4s", ks0_str, par0_str) == 2) {
                    uint32_t nt_enc = (uint32_t)strtoul(ks0_str, NULL, 16);
                    uint8_t par_enc = (uint8_t)strtoul(par0_str, NULL, 2);
                    fprintf(temp_fp, "%u|%u\n", nt_enc, par_enc);
                }
            }
        }
    }
    return 0;
}
