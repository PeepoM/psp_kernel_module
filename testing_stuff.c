#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>

static int hello_world_handler(module_t mod, int event, void *arg)
{
    switch (event)
    {
    case MOD_LOAD:
        uprintf("Greetings World! The kernel module has been loaded!\n");
        break;
    case MOD_UNLOAD:
        uprintf("Farewell! The kernel module has been unloaded!\n");
        break;
    default:
        return EOPNOTSUPP;
    }

    return 0;
}

static moduledata_t hello_mod = {
    "mymodule",
    hello_world_handler,
    NULL};

DECLARE_MODULE(mymodule, hello_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

int main(int argc, char *argv[])
{
    int i, opt, n = 0, skipped = 0, rc = EXIT_SUCCESS, pcap_rc;
    pkt_rc_t pkt_rc;
    pcap_t *in_pd = NULL, *out_pd = NULL;
    pcap_dumper_t *pdumper = NULL;
    char *in_pcap_file = DEFAULT_CLEARTEXT_PCAP_FILE,
         *out_pcap_file = DEFAULT_ENCRYPT_PCAP_FILE,
         *cfg_file = DEFAULT_ENCRYPT_CFG_FILE;
    struct stat stat_buf;
    struct pkt_context pkt_ctx;

    pkt_ctx.max_pkt_octets = ETH_JUMBO_MAX_OCTETS;
    pkt_ctx.out_pkt = NULL;
    pkt_ctx.next_iv = PSP_INITIAL_IV;
    pkt_ctx.scratch_buf = NULL;

    /* allocate packet buffers */
    pkt_ctx.out_pkt = calloc(1, pkt_ctx.max_pkt_octets);
    if (pkt_ctx.out_pkt == NULL)
    {
        fprintf(stderr, "calloc() failed\n");
        goto err_exit;
    }

    pkt_ctx.scratch_buf = calloc(1, pkt_ctx.max_pkt_octets);
    if (pkt_ctx.scratch_buf == NULL)
    {
        fprintf(stderr, "calloc() failed\n");
        goto err_exit;
    }

    /* process packets from input pcap file */
    while (1)
    {
        pcap_rc = pcap_next_ex(in_pd, &pkt_ctx.in_pcap_pkt_hdr,
                               (const u_char **)&pkt_ctx.in_pkt);
        if (pcap_rc == 1)
        {
            /* packet read without error from pcap file */
            pkt_rc = process_in_pkt(&pkt_ctx);
            if (pkt_rc == PKT_ERR)
            {
                goto err_exit;
            }
            else if (pkt_rc == PKT_SKIPPED)
            {
                skipped++;
            }
            else
            {
                /* write encrypted packet to output pcap file */
                pcap_dump((u_char *)pdumper, &pkt_ctx.out_pcap_pkt_hdr,
                          (u_char *)pkt_ctx.out_pkt);
                n++;
            }
        }
        else if (pcap_rc == PCAP_ERROR_BREAK)
        {
            /* no more packets to read */
            break;
        }
        else
        {
            pcap_perror(in_pd, "pcap_next_ex() failed");
            goto err_exit;
        }
    }

    printf("encrypted %d packets in %s, skipped %d packets\n", n, out_pcap_file,
           skipped);
    goto exit;

err_exit:
    fflush(stdout);
    fprintf(stderr, "psp encryption failed\n");
    fflush(stderr);
    rc = EXIT_FAILURE;

exit:
    free(pkt_ctx.scratch_buf);
    free(pkt_ctx.out_pkt);
    if (pdumper != NULL)
        pcap_dump_close(pdumper);
    if (out_pd != NULL)
        pcap_close(out_pd);
    if (in_pd != NULL)
        pcap_close(in_pd);

    exit(rc);
}

typedef enum
{                /* return codes for packet processsing */
  PKT_ENCRYPTED, /* success */
  PKT_SKIPPED,   /* packet not encrypted */
  PKT_ERR
} pkt_rc_t;

struct psp_encrypt_cfg
{ /* encryption config parms */
    struct psp_master_key master_key0;
    struct psp_master_key master_key1;
    uint32_t spi;
    psp_encap_t psp_encap;
    crypto_alg_t crypto_alg;
    /* crypt offset for transport mode, units = 4B */
    uint8_t transport_crypt_off;
    /* crypt offset for ipv4 packets in tunnel mode, units = 4B */
    uint8_t ipv4_tunnel_crypt_off;
    /* crypt offset for ipv6 packets in tunnel mode, units = 4B */
    uint8_t ipv6_tunnel_crypt_off;
    bool include_vc; /* include vc in psp header */
};

struct pkt_context
{
    uint32_t max_pkt_octets;
    struct psp_encrypt_cfg psp_cfg;
    struct psp_derived_key key;
    uint64_t next_iv;
    struct pcap_pkthdr *in_pcap_pkt_hdr;
    uint8_t *in_pkt;
    uint32_t eth_hdr_len;
    struct pcap_pkthdr out_pcap_pkt_hdr;
    uint8_t *out_pkt;
    uint8_t *scratch_buf;
};

/* get next psp initialization vector */
static inline uint64_t get_psp_iv(struct pkt_context *pkt_ctx)
{
    uint64_t iv;

    iv = HTONLL(pkt_ctx->next_iv);
    pkt_ctx->next_iv++;
    return iv;
}

static pkt_rc_t psp_encrypt(struct pkt_context *pkt_ctx, struct psp_hdr *psp,
                            uint32_t cleartext_len, uint8_t *cleartext,
                            uint32_t aad_len, uint8_t *ciphertext,
                            struct psp_icv *icv)
{
    int rc, len;
    uint8_t *aad = (uint8_t *)psp;
    struct aes_gcm_iv gcm_iv;
    EVP_CIPHER_CTX *ctx = NULL;

    memcpy(gcm_iv.octets, &psp->spi, PSP_SPI_OCTETS);
    memcpy(&gcm_iv.octets[PSP_SPI_OCTETS], &psp->iv, PSP_IV_OCTETS);

    /* create and initialize the cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "EVP_CIPHER_CTX_new() failed\n");
        goto err_exit;
    }

    /* initialize the encryption operation */
    if (pkt_ctx->psp_cfg.crypto_alg == AES_GCM_128)
        rc = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    else
        rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (rc != 1)
    {
        fprintf(stderr, "EVP_EncryptInit_ex() failed\n");
        goto err_exit;
    }

    /* initialize key and iv */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, pkt_ctx->key.octets, gcm_iv.octets) !=
        1)
    {
        fprintf(stderr, "EVP_EncryptInit_ex() failed\n");
        goto err_exit;
    }

    /* provide additional authentication data */
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
    {
        fprintf(stderr, "EVP_EncryptUpdate() failed\n");
        goto err_exit;
    }

    /* do encryption */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, cleartext, cleartext_len) != 1)
    {
        fprintf(stderr, "EVP_EncryptUpdate() failed\n");
        goto err_exit;
    }

    /* finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        fprintf(stderr, "EVP_EncryptFinal_ex() failed\n");
        goto err_exit;
    }

    /* get the icv */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, PSP_ICV_OCTETS,
                            icv->octets) != 1)
    {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl() failed\n");
        goto err_exit;
    }

    EVP_CIPHER_CTX_free(ctx);
    return PKT_ENCRYPTED;

err_exit:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    return PKT_ERR;
}

/* perform transport mode psp encapsulation */
static pkt_rc_t transport_encap(struct pkt_context *pkt_ctx)
{
    struct eth_hdr *eth;
    struct ipv4_hdr *ipv4, *out_ipv4;
    struct ipv6_hdr *ipv6, *out_ipv6;
    struct udp_hdr *psp_udp;
    struct psp_hdr *psp;
    struct psp_icv *out_icv;
    uint8_t *ip_proto, *in_pkt, *out_pkt, *out_l4, *buf, *in_encrypt,
        *out_encrypt, psp_ver;
    uint16_t etype, ip_len, *in_l4, sport, dport;
    uint32_t pkt_len, max_len, eth_hdr_len, ip_hdr_len, ip_payload_len,
        udp_hdr_len, vc_octets, psp_encap_octets, base_psp_hdr_len, psp_hdr_len,
        psp_payload_len, crypt_off, crypt_off_after_ext, encrypt_len, aad_len;
    uint64_t *vc;
    pkt_rc_t pkt_rc;

    in_pkt = pkt_ctx->in_pkt;
    eth = (struct eth_hdr *)in_pkt;
    eth_hdr_len = pkt_ctx->eth_hdr_len;
    pkt_len = pkt_ctx->in_pcap_pkt_hdr->len;
    max_len = pkt_ctx->max_pkt_octets - PSP_TRANSPORT_ENCAP_OCTETS;

    if (pkt_len > max_len)
    {
        fprintf(stderr, "invalid packet, too big, %u bytes\n", pkt_len);
        return PKT_ERR;
    }

    etype = ntohs(eth->etype);
    if (etype == IPV4_ETYPE)
    {
        ipv4 = (struct ipv4_hdr *)(in_pkt + eth_hdr_len);
        ip_proto = &ipv4->proto;
        ip_hdr_len = (ipv4->ver_ihl & IPV4_IHL_MASK) * IPV4_IHL_UNITS;
        psp_payload_len = pkt_len - (eth_hdr_len + ip_hdr_len);
    }
    else
    {
        ipv6 = (struct ipv6_hdr *)(in_pkt + eth_hdr_len);
        ip_proto = &ipv6->proto;
        switch (*ip_proto)
        {
        case IP_PROTO_UDP:
        case IP_PROTO_TCP:
            ip_hdr_len = sizeof(struct ipv6_hdr);
            psp_payload_len = pkt_len - (eth_hdr_len + ip_hdr_len);
            break;
        default:
            return PKT_SKIPPED;
        }
    }
    ip_payload_len = pkt_len - (eth_hdr_len + ip_hdr_len);

    crypt_off = pkt_ctx->psp_cfg.transport_crypt_off * PSP_CRYPT_OFFSET_UNITS;
    if (crypt_off > psp_payload_len)
    {
        fprintf(stderr, "skipping packet, crypt offset too big\n");
        return PKT_SKIPPED;
    }

    /*
     * build the psp-encapsulated packet
     *   - copy the eth and ip headers of input packet
     *   - insert the psp udp header
     *   - insert the psp header
     *   - copy crypt_off bytes from input packet starting at l4 header
     *   - compute icv and insert encrypted data
     *   - insert icv as psp trailer
     */
    out_pkt = pkt_ctx->out_pkt;
    memcpy(out_pkt, eth, eth_hdr_len + ip_hdr_len);

    if (pkt_ctx->psp_cfg.include_vc)
        vc_octets = PSP_HDR_VC_OCTETS;
    else
        vc_octets = 0;

    if (crypt_off > vc_octets)
        crypt_off_after_ext = crypt_off - vc_octets;
    else
        crypt_off_after_ext = 0;

    base_psp_hdr_len = sizeof(struct psp_hdr);
    psp_hdr_len = base_psp_hdr_len + vc_octets;
    psp_encap_octets = PSP_TRANSPORT_ENCAP_OCTETS + vc_octets;

    if (etype == IPV4_ETYPE)
    {
        ip_len = ntohs(ipv4->len);
        out_ipv4 = (struct ipv4_hdr *)(out_pkt + eth_hdr_len);
        out_ipv4->len = htons(ip_len + psp_encap_octets);
        out_ipv4->proto = IP_PROTO_UDP;
        out_ipv4->csum = 0;
        out_ipv4->csum = ipv4_hdr_csum(out_ipv4);
    }
    else
    {
        ip_len = ntohs(ipv6->plen);
        out_ipv6 = (struct ipv6_hdr *)(out_pkt + eth_hdr_len);
        out_ipv6->plen = htons(ip_len + psp_encap_octets);
        out_ipv6->proto = IP_PROTO_UDP;
    }

    psp_udp = (struct udp_hdr *)(out_pkt + eth_hdr_len + ip_hdr_len);
    in_l4 = (uint16_t *)(in_pkt + eth_hdr_len + ip_hdr_len);
    switch (*ip_proto)
    {
    case IP_PROTO_UDP:
    case IP_PROTO_TCP:
        /* set psp udp sport to simple hash of */
        /* port numbers from inner packet      */
        sport = ntohs(in_l4[0]);
        dport = ntohs(in_l4[1]);
        psp_udp->sport = htons(sport ^ dport);
        break;
    default:
        psp_udp->sport = htons(UDP_PORT_PSP);
        break;
    }
    psp_udp->dport = htons(UDP_PORT_PSP);
    psp_udp->len = htons(psp_payload_len + psp_encap_octets);
    psp_udp->csum = 0;
    udp_hdr_len = sizeof(struct udp_hdr);

    psp = (struct psp_hdr *)(((uint8_t *)psp_udp) + udp_hdr_len);
    psp->next_hdr = *ip_proto;
    if (pkt_ctx->psp_cfg.crypto_alg == AES_GCM_128)
        psp_ver = PSP_VER0;
    else
        psp_ver = PSP_VER1;
    if (pkt_ctx->psp_cfg.include_vc)
    {
        psp->hdr_ext_len = PSP_HDR_EXT_LEN_WITH_VC;
        psp->s_d_ver_v_1 =
            (psp_ver << PSP_HDR_VER_SHIFT) | PSP_HDR_FLAG_V | PSP_HDR_ALWAYS_1;
        vc = (uint64_t *)(((uint8_t *)psp) + base_psp_hdr_len);
        *vc = 0;
    }
    else
    {
        psp->hdr_ext_len = PSP_HDR_EXT_LEN_MIN;
        psp->s_d_ver_v_1 = (psp_ver << PSP_HDR_VER_SHIFT) | PSP_HDR_ALWAYS_1;
    }
    psp->crypt_off = pkt_ctx->psp_cfg.transport_crypt_off;
    psp->spi = htonl(pkt_ctx->psp_cfg.spi);
    psp->iv = get_psp_iv(pkt_ctx);

    out_l4 = ((uint8_t *)psp) + psp_hdr_len;
    memcpy(out_l4, in_l4, crypt_off_after_ext);

    /* build buffer for icv/encryption computation */
    buf = pkt_ctx->scratch_buf;
    memcpy(buf, psp, psp_hdr_len);
    memcpy(buf + psp_hdr_len, in_l4, ip_payload_len);

    /* compute icv and do encryption */
    in_encrypt = buf + base_psp_hdr_len + crypt_off;
    out_encrypt = ((uint8_t *)psp) + base_psp_hdr_len + crypt_off;
    encrypt_len = vc_octets + ip_payload_len - crypt_off;
    aad_len = base_psp_hdr_len + crypt_off;
    out_icv = (struct psp_icv *)(out_encrypt + encrypt_len);
    pkt_rc = psp_encrypt(pkt_ctx, psp, encrypt_len, in_encrypt, aad_len,
                         out_encrypt, out_icv);
    if (pkt_rc != PKT_ENCRYPTED)
        return pkt_rc;

    /* force corruption error if requested */
    if (force_corruption == true)
        psp->crypt_off |= PSP_CRYPT_OFFSET_RESERVED_BIT7;

    /* set pcap packet header fields for output packet */
    pkt_len += psp_encap_octets;
    pkt_ctx->out_pcap_pkt_hdr.caplen = pkt_len;
    pkt_ctx->out_pcap_pkt_hdr.len = pkt_len;
    pkt_ctx->out_pcap_pkt_hdr.ts = pkt_ctx->in_pcap_pkt_hdr->ts;

    return PKT_ENCRYPTED;
}