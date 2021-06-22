#ifndef _PROTO_TCP_H_
#define _PROTO_TCP_H_

// eftirlit7 (gpl2) - orthopteroid@gmail.com

bool prot_tcp_parse(struct psi *psi_out, uint32_t packet_id, void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

int prot_tcp_init(void);
void prot_tcp_exit(void);

#endif // _PROTO_TCP_H_
