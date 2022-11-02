#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

SEC("socket")
int do_stuff(struct __sk_buff *skb) {
    return 0;
}