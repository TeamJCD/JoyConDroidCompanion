/* patch_sym.c — in-place ELF64 .dynstr symbol rename + .gnu.hash update.
 * Usage: patch_sym <file> <old_sym> <new_sym>  (same-length names only) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ELF64 types (little-endian aarch64) */
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
} Elf64_Shdr;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
} Elf64_Sym;

static uint32_t gnu_hash(const char *s) {
    uint32_t h = 5381;
    for (unsigned char c; (c = (unsigned char)*s) != '\0'; s++)
        h = (h << 5) + h + c;
    return h;
}

int main(int argc, char *argv[]) {
    if (argc != 4) return 1;
    const char *path = argv[1], *old_sym = argv[2], *new_sym = argv[3];
    size_t olen = strlen(old_sym), nlen = strlen(new_sym);
    if (olen != nlen) return 1;

    FILE *f = fopen(path, "r+b");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);

    uint8_t *buf = malloc(fsz);
    if (!buf || (long)fread(buf, 1, fsz, f) != fsz) { fclose(f); free(buf); return 1; }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(buf + eh->e_shoff);
    const char *shstrtab = (const char *)(buf + shdrs[eh->e_shstrndx].sh_offset);

    Elf64_Shdr *dynstr_sh = NULL, *dynsym_sh = NULL, *gnuhash_sh = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        const char *sname = shstrtab + shdrs[i].sh_name;
        if (strcmp(sname, ".dynstr")   == 0) dynstr_sh  = &shdrs[i];
        if (strcmp(sname, ".dynsym")   == 0) dynsym_sh  = &shdrs[i];
        if (strcmp(sname, ".gnu.hash") == 0) gnuhash_sh = &shdrs[i];
    }
    if (!dynstr_sh) { fclose(f); free(buf); return 1; }

    /* Find \0<old_sym>\0 in .dynstr */
    uint8_t *ds = buf + dynstr_sh->sh_offset;
    size_t   ds_sz = dynstr_sh->sh_size;
    long str_off = -1;
    for (size_t i = 0; i < ds_sz - olen - 1; i++) {
        if (ds[i] == '\0' && memcmp(ds + i + 1, old_sym, olen) == 0
                && ds[i + 1 + olen] == '\0') {
            str_off = (long)(i + 1);
            break;
        }
    }
    if (str_off < 0) { fclose(f); free(buf); return 1; }

    /* Rename the string */
    memcpy(ds + str_off, new_sym, nlen);

    /* Update .gnu.hash if present */
    if (gnuhash_sh && dynsym_sh) {
        /* Find .dynsym entry with st_name == str_off */
        Elf64_Sym *syms = (Elf64_Sym *)(buf + dynsym_sh->sh_offset);
        int nsyms = (int)(dynsym_sh->sh_size / sizeof(Elf64_Sym));
        int sym_idx = -1;
        for (int i = 0; i < nsyms; i++) {
            if (syms[i].st_name == (uint32_t)str_off) { sym_idx = i; break; }
        }

        if (sym_idx >= 0) {
            uint8_t  *ht       = buf + gnuhash_sh->sh_offset;
            uint32_t  nbuckets = *(uint32_t *)(ht +  0);
            uint32_t  symndx   = *(uint32_t *)(ht +  4);
            uint32_t  maskwords= *(uint32_t *)(ht +  8);
            uint32_t  shift2   = *(uint32_t *)(ht + 12);
            uint64_t *bloom    = (uint64_t  *)(ht + 16);
            uint32_t *chains   = (uint32_t  *)(ht + 16 + maskwords * 8 + nbuckets * 4);

            if ((uint32_t)sym_idx >= symndx) {
                uint32_t h_new    = gnu_hash(new_sym);
                uint32_t cidx     = (uint32_t)sym_idx - symndx;
                uint32_t last_bit = chains[cidx] & 1u;

                /* Update chain value with new hash, preserving last-chain bit */
                chains[cidx] = (h_new & ~1u) | last_bit;

                /* Update bloom filter for new hash */
                uint32_t wi = (h_new / 64u) % maskwords;
                bloom[wi] |= (1ULL << (h_new % 64u))
                           | (1ULL << ((h_new >> shift2) % 64u));
            }
        }
    }

    /* Write modified buffer back */
    rewind(f);
    fwrite(buf, 1, fsz, f);
    fflush(f);
    fclose(f);
    free(buf);
    return 0;
}
