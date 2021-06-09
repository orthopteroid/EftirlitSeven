#ifndef _PROTO_UDP_H_
#define _PROTO_UDP_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com

bool prot_udp_parse(struct psi *psi_out, uint32_t packet_id, void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

int prot_udp_init(void);
void prot_udp_exit(void);

#endif // _PROTO_UDP_H_
