/*
 *  monocle
 *  src/main.c
 *
 *  Author: Vilmain Nicolas
 *  Contact: nicolas.vilmain@gmail.com
 *
 *  This file is part of monocle.
 *
 *  monocle is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  monocle is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with monocle.  If not, see <http://www.gnu.org/licenses/>.
 */

#include  "monocle.h"
#include  <getopt.h>

static int decode_program_options(int argc, char **argv, MONOCLE *monocle);
static int set_target(int argc, char **argv, MONOCLE *monocle);
static int parse_ip_args(const char *arg, uint8_t *mask, MONOCLE *monocle);
static void add_target_in_tab(int bit, uint8_t *mask, MONOCLE *monocle);
static void free_monocle(MONOCLE *monocle);
static int monocle_start(MONOCLE *monocle, struct ethsock_s *sock);
static int monocle_passiv(MONOCLE *monocle, int fdsock);
static int parse_response(struct arp_packet_s *ar, MONOCLE *monocle);
static void show_monocle_result(MONOCLE *monocle);
static void custom_output(MONOCLE *monocle, struct target_s *target);
static void classic_output(MONOCLE *monocle, struct target_s *target);
static void print_target_data(struct target_s *target, const char *offset_mac);
static char *get_date(time_t timestamp);
static int xstrtol_positiv_value(const char *str, int *dec);
static int set_signal_handler(MONOCLE *monocle);
static void signal_handler(int sig_num);
static void version(void);
static void usage(void);

int
main(int argc, char **argv)
{
    int ret;
    MONOCLE monocle;
    struct ethsock_s sock;

    debug = 0;
    gmono = &monocle;   /* just use in signal_handler */
    program_name = argv[0];
    ret = decode_program_options(argc, argv, &monocle);
    if (!ret) {
        if (get_ethsock(&sock, monocle.nc.nc_index,
                        monocle.nc.nc_name) == -1) {
            free_monocle(&monocle);
            return EXIT_FAILURE;
        }
        if ((monocle.opt & PASSIV))
            ret = monocle_passiv(&monocle, sock.fdsock);
        else
            ret = monocle_start(&monocle, &sock);
        close(sock.fdsock);
        show_monocle_result(&monocle);
    }
    free_monocle(&monocle);
    return (!ret) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int
decode_program_options(int argc, char **argv, MONOCLE *monocle)
{
    char *device_name = NULL;
    char current_opt;
    struct option const long_opt[] =
         {
              {"help",           no_argument,       0, 'h'},
              {"version",        no_argument,       0, 'V'},
              {"debug",          no_argument,       0, 'd'},
              {"verbose",        no_argument,       0, 'v'},
              {"timer",          no_argument,       0, 't'},
              {"send-timeout",   required_argument, 0, 'e'},
              {"no-cols-header", no_argument,       0, 'H'},
              {"device",         required_argument, 0, 'i'},
              {"passiv",         no_argument,       0, 'p'},
              {"wait-time",      required_argument, 0, 'w'},
              {"max-pkt",        required_argument, 0, 'm'},
              {"stats",          no_argument,       0, 's'},
              {"vendor",         no_argument,       0, 'o'},
              {"output-format",  required_argument, 0, 'f'},
              {0,                0,                 0, 0}
         };

    memset(monocle, 0, sizeof(MONOCLE));
    monocle->target = xcalloc(256 * sizeof(struct target_s *));
    do {
        current_opt = getopt_long(argc, argv, "hVdpi:w:m:tHsve:of:", long_opt, NULL);
        switch (current_opt) {
        case 'h':
            usage();
            break;
        case 'V':
            version();
            break;
        case 'd':
            debug = 1;
            break;
        case 'v':
            monocle->opt |= VERBOSE;
            break;
        case 'i':
            device_name = argv[optind - 1];
            break;
        case 'p':
            monocle->opt |= PASSIV;
            break;
        case 'w':
            if (xstrtol_positiv_value(optarg, &monocle->time))
                return -1;
            break;
        case 'm':
            if (xstrtol_positiv_value(optarg, &monocle->max_packet))
                return -1;
            break;
        case 'e':
            if (*optarg == 'm') {
                if (xstrtol_positiv_value((optarg + 1), &monocle->usec_send))
                    return -1;
            }
            else {
                if (xstrtol_positiv_value(optarg, &monocle->sec_send))
                    return -1;
            }
            break;
        case 't':
            monocle->opt |= MS_TIME;
            break;
        case 'H':
            monocle->opt |= NO_SHOW_HDR;
            break;
        case 's':
            monocle->stat = xcalloc(sizeof(struct pktstat_s));
            break;
        case 'o':
            open_file_oui(monocle);
            break;
        case 'f':
            monocle->output_format = argv[optind - 1];
            break;
        }
    } while (current_opt != -1);
    if (get_netconf(&monocle->nc, device_name)
        || set_target(argc, argv, monocle))
        return -1;
    if (monocle->output_format) {
        if (strstr(monocle->output_format, "%V") && !monocle->file_oui)
            open_file_oui(monocle);
        if (strstr(monocle->output_format, "%T"))
            monocle->opt |= MS_TIME;
    }
    return set_signal_handler(monocle);
}

static int
set_target(int argc, char **argv, MONOCLE *monocle)
{
    int i;
    uint8_t mask[4];
    char ip[17];

    memcpy(mask, &monocle->nc.nc_ipv4, 3);
    if (optind == argc) {
        mask[3] = 0;
        printf("you not set target, target list is ");
        if (inet_ntop(AF_INET, mask, ip, 16))
            printf("%s-255, try --help for program usage\n", ip);
        else
            printf("0 at x.x.x.255, try --help for program usage\n");
        for (i = 0; i < 256; i++)
            add_target_in_tab(i, mask, monocle);
    }
    else {
        do {
            if (parse_ip_args(argv[optind], mask, monocle)) {
                error("invalid argument <%s>\n", argv[optind]);
                return -1;
            }
        } while (((++optind) - argc));
    }
    return 0;
}

static int
parse_ip_args(const char *arg, uint8_t *mask, MONOCLE *monocle)
{
    int bit;
    int old_bit;
    char delim;

    delim = 0;
    old_bit = 0;
    do {
        if (*arg != ',' && *arg != '-') {
            bit = 0;
            while (*arg && *arg != ',' && *arg != '-') {
                if (*arg < '0' || *arg > '9')
                    return -1;
                bit *= 10;
                bit += *arg - '0';
                arg++;
            }
            if (bit > 255)
                return -1;
            if (delim == '-') {
                if (old_bit > bit) {
                    for (old_bit--; old_bit >= bit; old_bit--)
                        add_target_in_tab(old_bit, mask, monocle);
                }
                else {
                    for (old_bit++; old_bit <= bit; old_bit++)
                        add_target_in_tab(old_bit, mask, monocle);
                }
            }
            else
                add_target_in_tab(bit, mask, monocle);
            old_bit = bit;
        }
        delim = *arg;
    } while (*arg++);
    return 0;
}

static void
add_target_in_tab(int bit, uint8_t *mask, MONOCLE *monocle)
{
    if (!monocle->target[bit]) {
        monocle->nhost++;
        monocle->target[bit] = xcalloc(sizeof(struct target_s));
        mask[3] = bit;
        COPY_IP (monocle->target[bit]->ip, mask);
        if (!memcmp(mask, &monocle->nc.nc_ipv4, 4))
            COPY_MAC (monocle->target[bit]->mac, monocle->nc.nc_mac);
    }
}

static void
free_monocle(MONOCLE *monocle)
{
    int i;

    if (monocle->stat)
        free(monocle->stat);
    if (monocle->target) {
        for (i = 0; i < 256; i++) {
            if (monocle->target[i])
                free(monocle->target[i]);
        }
        free(monocle->target);
        if (monocle->file_oui)
            fclose(monocle->file_oui);
    }
}

static int
monocle_start(MONOCLE *monocle, struct ethsock_s *sock)
{
    int i;
    int ret;
    int nhost;
    struct arp_packet_s ar_send;
    struct arp_packet_s ar_recv;
    struct timeval buf_time;

    if ((monocle->opt & VERBOSE)) {
        printf("%s monocle started with %d target, "
               "use net device %s, CTRL-C for exit program before the end\n",
               get_date(time(NULL)), monocle->nhost,
               monocle->nc.nc_name);
    }
    i = 0;
    nhost = monocle->nhost;
    memset(&ar_send, 0, ARP_SIZE);
    COPY_MAC (ar_send.eth_src, monocle->nc.nc_mac);
    COPY_MAC (ar_send.eth_dst, BROADCAST_ADDR);
    ar_send.eth_protocol = htons(ETH_ARP);
    ar_send.arp_hrd = htons(1);
    ar_send.arp_protocol = htons(ETH_IP);
    ar_send.arp_hln = MAC_SIZE;
    ar_send.arp_pln = IP4_SIZE;
    ar_send.arp_opcode = htons(ARP_OPCODE_REQUEST);
    COPY_MAC (ar_send.arp_mac_src, monocle->nc.nc_mac);
    COPY_IP (ar_send.arp_ip_src, &monocle->nc.nc_ipv4);
    while (nhost && i < 256) {
        while (i < 256) {
            if (monocle->target[i]) {
                if (monocle->sec_send)
                    sleep(monocle->sec_send);
                else if (monocle->usec_send)
                    usleep(monocle->usec_send);
                COPY_IP (ar_send.arp_ip_dst, &monocle->target[i]->ip);
                if (ethsend(sock, &ar_send, ARP_SIZE) == -1)
                    return -1;
                if ((monocle->opt & MS_TIME)) {
                    gettimeofday(&buf_time, NULL);
                    monocle->target[i]->usec_send = buf_time.tv_usec;
                }
                i++;
                break;
            }
            i++;
        }
        if (!(--nhost))
            usleep(25000);
        do {
            ret = ethrecv(sock->fdsock, &ar_recv, monocle);
            if (ret == -1)
                return -1;
            else if (ret && (ar_recv.arp_opcode == htons(ARP_OPCODE_REPLY))) {
                if (monocle->stat)
                    monocle->stat->ps_arp_query++;
                ret = parse_response(&ar_recv, monocle);
                if (ret > -1 && (monocle->opt & MS_TIME)) {
                    gettimeofday(&buf_time, NULL);
                    monocle->target[ret]->usec_recv = buf_time.tv_usec;
                }
            }
        } while (ret);
    }
    return 0;
}

static int
monocle_passiv(MONOCLE *monocle, int fdsock)
{
    int ret;
    struct arp_packet_s ar;

    if ((monocle->opt & VERBOSE)) {
        printf("%s monocle started with %d target, "
               "use net device %s, CTRL-C for exit program\n",
               get_date(time(NULL)), monocle->nhost,
               monocle->nc.nc_name);
    }
    if (monocle->time)
        monocle->start_time = time(NULL);
    for (;;) {
        if ((monocle->time
             && (time(NULL) - monocle->start_time) > monocle->time)
            || (monocle->max_packet
                && monocle->nrecv == monocle->max_packet))
            break;
        ret = ethrecv(fdsock, &ar, monocle);
        if (ret == -1)
            return -1;
        else if (ret && (ar.arp_opcode == htons(ARP_OPCODE_REPLY))) {
            if (monocle->stat)
                monocle->stat->ps_arp_query++;
            (void) parse_response(&ar, monocle);
        }
        else if (ret && (ar.arp_opcode == htons(ARP_OPCODE_REQUEST))) {
            if (monocle->stat)
                monocle->stat->ps_arp_req++;
            (void) parse_response(&ar, monocle);
        }
    }
    return 0;
}

static int
parse_response(struct arp_packet_s *ar, MONOCLE *monocle)
{
    int idx;

    idx = ar->arp_ip_src[3];
    if (monocle->target[idx] && !CMP_MAC (monocle->target[idx]->mac,
                                          NULL_MAC)) {
        monocle->result++;
        COPY_MAC (monocle->target[idx]->mac, ar->eth_src);
        if ((monocle->opt & VERBOSE)) {
            printf("VERBOSE: find host : ");
            print_target_data(monocle->target[idx], " ");
            putchar('\n');
            fflush(stdout);
        }
        return idx;
    }
    return -1;
}

static void
show_monocle_result(MONOCLE *monocle)
{
    int i;
    void (*start_output)(MONOCLE *, struct target_s *) = NULL;

    if (!monocle->result) {
        puts("no result find");
        return;
    }
    start_output = (monocle->output_format) ? &custom_output : &classic_output;
    if (!(monocle->opt & NO_SHOW_HDR) && !monocle->output_format) {
        printf("IP\r\t\tMAC");
        if ((monocle->opt & MS_TIME) && !(monocle->opt & PASSIV))
            printf("\r\t\t\t\t\tTIME");
        if (monocle->file_oui)
            printf("\r\t\t\t\t\t\tVENDOR");
        putchar('\n');
    }
    for (i = 0; i < 256; i++) {
        if (monocle->target[i] && CMP_MAC (monocle->target[i]->mac, NULL_MAC)) {
            start_output(monocle, monocle->target[i]);
            putchar('\n');
        }
    }
    if (monocle->stat) {
        printf("packet(s) tot send/recv: %d/%d\n"
               "packet(s) arp recevied total/request/query: %d/%d/%d\n",
               (monocle->opt & PASSIV) ? 0 : monocle->nhost, monocle->nrecv, monocle->stat->ps_arp,
               monocle->stat->ps_arp_req, monocle->stat->ps_arp_query);
    }
}

static void
custom_output(MONOCLE *monocle, struct target_s *target)
{
    int diff_time;
    char ip[17];
    register char *format = NULL;

    format = monocle->output_format;
    while (*format) {
        if (*(format) == '%' && *(format + 1)) {
            switch (*(format + 1)) {
            case 'I':
                if (inet_ntop(AF_INET, target->ip, ip, 16))
                    printf("%s", ip);
                format++;
                break;
            case 'M':
                printf("%02x:%02x:%02x:%02x:%02x:%02x",
                       PRINT_MAC_ADDRS (target->mac));
                format++;
                break;
            case 'V':
                file_oui_search_mac_vendor(monocle->file_oui, target->mac);
                format++;
                break;
            case 'T':
                if ((monocle->opt & MS_TIME) && !(monocle->opt & PASSIV)) {
                    diff_time = (target->usec_recv - target->usec_send) / 1000;
                    printf("%d ms", (diff_time < 1) ? 0 : diff_time);
                }
                format++;
                break;
            default:
                putchar('%');
                break;
            }
        }
        else if (*(format) == '\\' && *(format + 1)) {
            switch (*(format + 1)) {
            case 'n':
                putchar('\n');
                format++;
                break;
            case 't':
                putchar('\t');
                format++;
                break;
            default:
                putchar('\\');
                break;
            }
        }
        else
            putchar(*format);
        format++;
    }
}

static void
classic_output(MONOCLE *monocle, struct target_s *target)
{
    int diff_time;

    print_target_data(target, "\r\t\t");
    if ((monocle->opt & MS_TIME) && !(monocle->opt & PASSIV)) {
        diff_time = (target->usec_recv - target->usec_send) / 1000;
        printf("\r\t\t\t\t\t%d ms", (diff_time < 1) ? 0 : diff_time);
    }
    if (monocle->file_oui) {
        printf("\r\t\t\t\t\t\t");
        file_oui_search_mac_vendor(monocle->file_oui, target->mac);
    }
    if (!memcmp(target->ip, &monocle->nc.nc_ipv4, 4) && !monocle->file_oui)
        printf(" (is you)");
}

static void
print_target_data(struct target_s *target, const char *offset_mac)
{
    char ip[17];

    if (inet_ntop(AF_INET, target->ip, ip, 16)) {
        printf("%s %s%02x:%02x:%02x:%02x:%02x:%02x",
               ip, offset_mac, PRINT_MAC_ADDRS (target->mac));
    }
}

static char *
get_date(time_t timestamp)
{
    char *p_date;
    struct tm *tm = NULL;

    tm = localtime(&timestamp);
    if (!tm)
        return "date=unknow";
    strftime(date, DATESIZE - 1, "%G-%m-%d %T", tm);
    p_date = date;
    return p_date;
}

static int
xstrtol_positiv_value(const char *str, int *dec)
{
    char *err = NULL;

    *dec = strtol(str, &err, 0);
    if (*err != '\0') {
        error("%s is not integer value\n", str);
        return -1;
    }
    if (*dec < 1) {
        error("%s is not positiv value\n", str);
        return -1;
    }
    return 0;
}

static int
set_signal_handler(MONOCLE *monocle)
{
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = &signal_handler;
    if (sigaction(SIGINT, &sigact, NULL) == -1) {
        DEBUG (2);
        error("sigaction(SIGINT): %s\n", strerror(errno));
        if ((monocle->opt & PASSIV) && !monocle->max_packet
            && !monocle->time)
            return -1;
    }
    return 0;
}

static void
signal_handler(int sig_num)
{
    (void) sig_num;
    puts("\rsignal SIGINT recevied !");
    show_monocle_result(gmono);
    free_monocle(gmono);
    exit(EXIT_SUCCESS);
}

static void
version(void)
{
    puts("monocle version 1.1");
    exit(EXIT_SUCCESS);
}

static void
usage(void)
{
    printf("%s [TARGET] [OPTIONS] ...\n"
           "If you don't define any target, all hosts in the network will be scanned\n"
           "If you want to scan only x.x.x.1 and x.x.x.17 hosts you\n"
           "have to define it such as ./monocle 1,17\n"
           "you can define a host range in this way: ./monocle 1-50\n"
           "it will scan all of the hosts from 1 to 50 (included)\n"
           "for instance: in order to scan x.x.x.2/4/6/8/10-50 hosts -> ./monocle 2,4,6,8,10-50\n"
           "  -h, --help                 show usage and exit program\n"
           "  -V, --version              show program version and exit\n"
           "  -d, --debug                set debug mode\n"
           "  -v, --verbose              set verbose mode\n"
           "  -t, --timer                show diff time to send and recv packet\n"
           "  -H, --no-cols-header       not print header for result scan\n"
           "  -i, --device               set network interface\n"
           "  -p, --passiv               not send, just listen and catch packet\n"
           "  -w, --wait-time            time to the program wait arp response (just with --passiv)\n"
           "  -m, --max-pkt              max packet recvied (just with --passiv)\n"
           "  -s, --stats                show packet stats\n"
           "  -e, --send-timeout         wait time for sending next packet\n"
           "                             exemple: 10, wait 10second, m10 wait 10 microsecond\n"
           "  -o, --vendor               show mac vendor\n"
           "  -f, --output-format        set your output format\n"
           "                             %%I print IP addres\n"
           "                             %%M print MAC address\n"
           "                             %%T print diff time\n"
           "                             %%V print MAC vendor\n"
           "                             \\t tabulation\n"
           "                             \\n ret line\n"
           "                             example: --output-format \"ip = %%I, mac = %%M, vendor = %%V\"\n",
           program_name);
    exit(EXIT_SUCCESS);
}
