#include <stdint.h>
#include <stdbool.h>

// the order of these two is very important
#include <wireshark/config.h>
#include <epan/packet.h>

#include <wireshark/epan/dissectors/packet-tcp.h>

#include <gmodule.h>

G_MODULE_EXPORT gchar version[30] = "1.0";

static int proto_remoting = -1;

static const value_string msg_type_names[] = {
    { 0x00, "Greeting" },
    { 0x01, "Capabilities" },
    { 0x02, "Auth Request" },
    { 0x03, "Auth Challenge" },
    { 0x04, "Auth Response" },
    { 0x05, "Auth Complete" },
    { 0x06, "Auth Rejected" },
    { 0x07, "Start TLS" },
    { 0x08, "NAK" },
    { 0x10, "Channel Open Request" },
    { 0x11, "Channel Open Ack" },
    { 0x12, "Channel Open Service Not Found" },
    { 0x13, "Channel Open Service Error" },
    { 0x20, "Channel Shutdown Write" },
    { 0x21, "Channel Close" },
    { 0x30, "Message Data" },
    { 0x31, "Message Window Open" },
    { 0x32, "Message Async Close" },
    { 0xF0, "Connection Alive" },
    { 0xF1, "Connection Alive Ack" },
    { 0xFF, "Connection Close" },
    { 0, 0 }
};

static int hf_remoting_pkt_length = -1;
static int hf_remoting_pkt_type = -1;
static int hf_remoting_chanid = -1;
static int hf_remoting_msgid = -1;
static int hf_remoting_msg_flags = -1;
static int hf_remoting_msg_flag_new = -1;
static int hf_remoting_msg_flag_eof = -1;
static int hf_remoting_msg_flag_cancel = -1;
static int hf_remoting_msg_window = -1;

static int hf_remoting_svcparam = -1;
static int hf_remoting_svcparam_name = -1;
static int hf_remoting_svcparam_imws = -1;
static int hf_remoting_svcparam_omws = -1;
static int hf_remoting_svcparam_iml = -1;
static int hf_remoting_svcparam_oml = -1;
static int hf_remoting_svcparam_imms = -1;
static int hf_remoting_svcparam_omms = -1;
static int hf_remoting_svcparam_unk = -1;
static int hf_remoting_svcparam_unk_cont = -1;

static int hf_remoting_grt = -1;
static int hf_remoting_grt_server = -1;
static int hf_remoting_grt_unk = -1;
static int hf_remoting_grt_unk_cont = -1;

static int hf_remoting_cap = -1;
static int hf_remoting_cap_version = -1;
static int hf_remoting_cap_saslmech = -1;
static int hf_remoting_cap_starttls = -1;
static int hf_remoting_cap_endpoint_name = -1;
static int hf_remoting_cap_msgclose = -1;
static int hf_remoting_cap_vstr = -1;
static int hf_remoting_cap_chan_in = -1;
static int hf_remoting_cap_chan_out = -1;
static int hf_remoting_cap_unk = -1;
static int hf_remoting_cap_unk_cont = -1;

static gint ett_remoting = -1;
static gint ett_svcparam = -1;
static gint ett_svcparam_unk = -1;
static gint ett_grt = -1;
static gint ett_grt_unk = -1;
static gint ett_cap = -1;
static gint ett_cap_unk = -1;

static void dissect_remoting_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Remoting");
    // clear info column
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_remoting, tvb, 0, -1, ENC_NA);
        proto_tree *remoting_tree = proto_item_add_subtree(ti, ett_remoting);
        proto_tree_add_item(remoting_tree, hf_remoting_pkt_length, tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(remoting_tree, hf_remoting_pkt_type, tvb, 4, 1, ENC_BIG_ENDIAN);
        uint8_t pkt_type = (uint8_t) tvb_get_guint8(tvb, 4);
        if (pkt_type == 0x00) {
            // greeting
            proto_item *params_item = proto_tree_add_item(remoting_tree, hf_remoting_grt, tvb, 5, -1, ENC_NA);
            proto_tree *params_tree = proto_item_add_subtree(params_item, ett_grt);
            gint p = 5;
            while (p < tvb_length(tvb)) {
                guint pid, plen;
                pid = tvb_get_guint8(tvb, p++);
                plen = tvb_get_guint8(tvb, p++);
                switch (pid) {
                    case 0: {
                        proto_tree_add_item(params_tree, hf_remoting_grt_server, tvb, p, plen, ENC_UTF_8);
                        break;
                    }
                    default: {
                        proto_item *unk_item = proto_tree_add_item(params_tree, hf_remoting_grt_unk, tvb, p - 2, 1, ENC_BIG_ENDIAN);
                        proto_tree *unk_tree = proto_item_add_subtree(unk_item, ett_grt_unk);
                        proto_tree_add_item(unk_tree, hf_remoting_grt_unk_cont, tvb, p, plen, ENC_NA);
                        break;
                    }
                }
                p += plen;
            }
        } else if (pkt_type == 0x01) {
            // capabilities
            proto_item *params_item = proto_tree_add_item(remoting_tree, hf_remoting_cap, tvb, 5, -1, ENC_NA);
            proto_tree *params_tree = proto_item_add_subtree(params_item, ett_cap);
            gint p = 5;
            while (p < tvb_length(tvb)) {
                guint pid, plen;
                pid = tvb_get_guint8(tvb, p++);
                plen = tvb_get_guint8(tvb, p++);
                switch (pid) {
                    case 0: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_version, tvb, p, plen, ENC_BIG_ENDIAN);
                        break;
                    }
                    case 1: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_saslmech, tvb, p, plen, ENC_UTF_8);
                        break;
                    }
                    case 2: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_starttls, tvb, p, plen, ENC_NA);
                        break;
                    }
                    case 3: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_endpoint_name, tvb, p, plen, ENC_UTF_8);
                        break;
                    }
                    case 4: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_msgclose, tvb, p, plen, ENC_NA);
                        break;
                    }
                    case 5: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_vstr, tvb, p, plen, ENC_UTF_8);
                        break;
                    }
                    case 6: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_chan_in, tvb, p, plen, ENC_BIG_ENDIAN);
                        break;
                    }
                    case 7: {
                        proto_tree_add_item(params_tree, hf_remoting_cap_chan_out, tvb, p, plen, ENC_BIG_ENDIAN);
                        break;
                    }
                    default: {
                        proto_item *unk_item = proto_tree_add_item(params_tree, hf_remoting_cap_unk, tvb, p - 2, 1, ENC_BIG_ENDIAN);
                        proto_tree *unk_tree = proto_item_add_subtree(unk_item, ett_cap_unk);
                        proto_tree_add_item(unk_tree, hf_remoting_cap_unk_cont, tvb, p, plen, ENC_NA);
                        break;
                    }
                }
                p += plen;
            }
            
        } else if (pkt_type >= 0x10 && pkt_type <= 0x3F) {
            proto_tree_add_item(remoting_tree, hf_remoting_chanid, tvb, 5, 4, ENC_BIG_ENDIAN);
            if (pkt_type == 0x10 || pkt_type == 0x11) {
                proto_item *params_item = proto_tree_add_item(remoting_tree, hf_remoting_svcparam, tvb, 9, -1, ENC_NA);
                proto_tree *params_tree = proto_item_add_subtree(params_item, ett_svcparam);
                gint p = 9;
                for (;;) {
                    guint pid, plen;
                    pid = tvb_get_guint8(tvb, p++);
                    if (pid == 0) return;
                    plen = tvb_get_guint8(tvb, p++);
                    switch (pid) {
                        case 1: {
                            proto_tree_add_item(params_tree, hf_remoting_svcparam_name, tvb, p, plen, ENC_UTF_8);
                            break;
                        }
                        case 0x80: {
                            proto_tree_add_item(params_tree, hf_remoting_svcparam_imws, tvb, p, plen, ENC_BIG_ENDIAN);
                            break;
                        }
                        case 0x81: {
                            proto_tree_add_item(params_tree, hf_remoting_svcparam_iml, tvb, p, plen, ENC_BIG_ENDIAN);
                            break;
                        }
                        case 0x82: {
                            proto_tree_add_item(params_tree, hf_remoting_svcparam_omws, tvb, p, plen, ENC_BIG_ENDIAN);
                            break;
                        }
                        case 0x83: {
                            proto_tree_add_item(params_tree, hf_remoting_svcparam_oml, tvb, p, plen, ENC_BIG_ENDIAN);
                            break;
                        }
                        case 0x84: {
                            proto_tree_add_item(params_tree, hf_remoting_svcparam_imms, tvb, p, plen, ENC_BIG_ENDIAN);
                            break;
                        }
                        case 0x85: {
                            proto_tree_add_item(params_tree, hf_remoting_svcparam_omms, tvb, p, plen, ENC_BIG_ENDIAN);
                            break;
                        }
                        default: {
                            proto_item *unk_item = proto_tree_add_item(params_tree, hf_remoting_svcparam_unk, tvb, p - 2, 1, ENC_BIG_ENDIAN);
                            proto_tree *unk_tree = proto_item_add_subtree(unk_item, ett_svcparam_unk);
                            proto_tree_add_item(unk_tree, hf_remoting_svcparam_unk_cont, tvb, p, plen, ENC_NA);
                            break;
                        }
                    }
                    p += plen;
                }
            } else if (pkt_type >= 0x30) {
                proto_tree_add_item(remoting_tree, hf_remoting_msgid, tvb, 9, 2, ENC_BIG_ENDIAN);
                if (pkt_type == 0x30) {
                    proto_tree_add_item(remoting_tree, hf_remoting_msg_flags, tvb, 11, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(remoting_tree, hf_remoting_msg_flag_eof, tvb, 11, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(remoting_tree, hf_remoting_msg_flag_new, tvb, 11, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(remoting_tree, hf_remoting_msg_flag_cancel, tvb, 11, 1, ENC_BIG_ENDIAN);
                } else if (pkt_type == 0x31) {
                    proto_tree_add_item(remoting_tree, hf_remoting_msg_window, tvb, 11, 4, ENC_BIG_ENDIAN);
                }
            }
        }
    }
}

static guint get_remoting_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset) {
    return (guint) tvb_get_ntohl(tvb, offset) + 4;
}

static void dissect_remoting(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_remoting_message_len, dissect_remoting_msg);
}

void plugin_register(void) {
    // packet framing info
    static hf_register_info hf[] = {
        { &hf_remoting_pkt_length, { "Remoting Length",     "remoting.length", FT_UINT32, BASE_DEC, 0,                    0x0, 0, HFILL }},
        { &hf_remoting_pkt_type,   { "Remoting Type",       "remoting.type",   FT_UINT8,  BASE_HEX, VALS(msg_type_names), 0x0, 0, HFILL }},
        { &hf_remoting_chanid,     { "Remoting Channel ID", "remoting.chanid", FT_UINT32, BASE_HEX, 0,                    0x0, 0, HFILL }},
        { &hf_remoting_msgid,      { "Remoting Message ID", "remoting.msgid",  FT_UINT16, BASE_HEX, 0,                    0x0, 0, HFILL }},

        { &hf_remoting_msg_flags,       { "Remoting Message Flags", "remoting.msgflags",        FT_UINT8,   BASE_HEX, 0, 0x0, 0, HFILL }},
        { &hf_remoting_msg_flag_cancel, { "Cancelled",              "remoting.msgflags.cancel", FT_BOOLEAN, 8,        0, 0x4, 0, HFILL }},
        { &hf_remoting_msg_flag_new,    { "New Message",            "remoting.msgflags.new",    FT_BOOLEAN, 8,        0, 0x2, 0, HFILL }},
        { &hf_remoting_msg_flag_eof,    { "End of Message",         "remoting.msgflags.eom",    FT_BOOLEAN, 8,        0, 0x1, 0, HFILL }},

        { &hf_remoting_msg_window, { "Remoting Window Adjustment", "remoting.msgwindow", FT_UINT32, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},

        { &hf_remoting_svcparam,          { "Service Parameters",       "remoting.svcparam",          FT_NONE,   0,            0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_name,     { "Service Name",             "remoting.svcparam.name",     FT_STRING, BASE_NONE,    0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_imws,     { "Inbound Msg Window Size",  "remoting.svcparam.imws",     FT_UINT32, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_omws,     { "Outbound Msg Window Size", "remoting.svcparam.omws",     FT_UINT32, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_iml,      { "Inbound Msg Limit",        "remoting.svcparam.iml",      FT_UINT16, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_oml,      { "Outbound Msg Limit",       "remoting.svcparam.oml",      FT_UINT16, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_imms,     { "Inbound Msg Max Size",     "remoting.svcparam.imms",     FT_UINT64, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_omms,     { "Outbound Msg Max Size",    "remoting.svcparam.omms",     FT_UINT64, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_unk,      { "Unknown",                  "remoting.svcparam.unk",      FT_UINT8,  BASE_HEX,     0, 0x0, 0, HFILL }},
        { &hf_remoting_svcparam_unk_cont, { "Content",                  "remoting.svcparam.unk.cont", FT_BYTES,  BASE_NONE,    0, 0x0, 0, HFILL }},

        { &hf_remoting_grt,          { "Greeting Parameters", "remoting.grt",          FT_NONE,   0,         0, 0x0, 0, HFILL }},
        { &hf_remoting_grt_server,   { "Server Name",         "remoting.grt.server",   FT_STRING, BASE_NONE, 0, 0x0, 0, HFILL }},
        { &hf_remoting_grt_unk,      { "Unknown",             "remoting.grt.unk",      FT_UINT8,  BASE_HEX,  0, 0x0, 0, HFILL }},
        { &hf_remoting_grt_unk_cont, { "Content",             "remoting.grt.unk.cont", FT_BYTES,  BASE_NONE, 0, 0x0, 0, HFILL }},
        
        { &hf_remoting_cap,               { "Capability Parameters",       "remoting.cap",          FT_NONE,   0,            0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_version,       { "Protocol Version",            "remoting.cap.version",  FT_UINT8,  BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_saslmech,      { "SASL Mechanism",              "remoting.cap.saslmech", FT_STRING, BASE_NONE,    0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_starttls,      { "STARTTLS Supported",          "remoting.cap.starttls", FT_NONE,   0,            0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_endpoint_name, { "Endpoint Name",               "remoting.cap.endpoint", FT_STRING, BASE_NONE,    0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_msgclose,      { "Supports Msg Close Protocol", "remoting.cap.msgclose", FT_NONE,   0,            0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_vstr,          { "Impl Version",                "remoting.cap.vstr",     FT_STRING, BASE_NONE,    0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_chan_in,       { "Inbound Channel Limit",       "remoting.cap.chanin",   FT_UINT16, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_chan_out,      { "Outbound Channel Limit",      "remoting.cap.chanout",  FT_UINT16, BASE_HEX_DEC, 0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_unk,           { "Unknown",                     "remoting.cap.unk",      FT_UINT8,  BASE_HEX,     0, 0x0, 0, HFILL }},
        { &hf_remoting_cap_unk_cont,      { "Content",                     "remoting.cap.unk.cont", FT_BYTES,  BASE_NONE,    0, 0x0, 0, HFILL }},
    };
    // protocol subtree
    static gint *ett[] = { &ett_remoting, &ett_svcparam, &ett_svcparam_unk, &ett_grt, &ett_grt_unk, &ett_cap, &ett_cap_unk };

    proto_remoting = proto_register_protocol("JBoss Remoting", "Remoting", "remoting");
    proto_register_field_array(proto_remoting, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void plugin_reg_handoff(void) {
    static dissector_handle_t remoting_handle;
    remoting_handle = create_dissector_handle(dissect_remoting, proto_remoting);
    dissector_add_uint("tcp.port", 9999, remoting_handle);
}

