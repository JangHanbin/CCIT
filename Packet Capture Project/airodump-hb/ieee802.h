#ifndef IEEE802_H
#define IEEE802_H

#include <iostream>

#pragma pack(push,1)


static uint8_t ieeeOUI[]={0x00,0x0f,0xac};
static uint8_t microsof[]={0x00,0x50,0xf2};
struct Radiotap{
    uint8_t header_revision;
    uint8_t header_pad;
    uint16_t header_length;

    /**************************Present flags******************************/

    uint32_t TSFT:1;
    uint32_t flags:1;
    uint32_t rate:1;
    uint32_t channel:1;
    uint32_t FHSS:1;
    uint32_t dBm_antenna_signal:1;
    uint32_t dBm_antenna_noise:1;
    uint32_t lock_quality:1;
    uint32_t TX_Attenuation:1;
    uint32_t dB_TX_Attenuation:1;
    uint32_t dBm_TX_power:1;
    uint32_t antenna:1;
    uint32_t dB_antenna_signal:1;
    uint32_t dB_antenna_noise:1;
    uint32_t RX_flags:1;
    uint32_t present_padding:3;
    uint32_t channel_plus:1;
    uint32_t MCS_information:1;
    uint32_t A_MPDU_status:1;
    uint32_t VHT_information:1;
    uint32_t reserved:7;
    uint32_t radiotap_NS_next:1;
    uint32_t vendor_NS_next:1;
    uint32_t ext:1;
    /**************************Present flags******************************/


    /**************************flags**************************************/

    uint8_t CFP:1;
    uint8_t preamble:1;
    uint8_t WEP:1;
    uint8_t fragmentation:1;
    uint8_t FCS_at_end:1;
    uint8_t data_pad:1;
    uint8_t bad_FCS:1;
    uint8_t short_GI:1;

    /**************************flags**************************************/

    uint8_t data_rate;





}typedef Radiotap;

struct Channel{
    uint16_t channel_frequency;

    /**************************channel flags******************************/
    uint16_t channel_padding:4;
    uint16_t turbo:1;
    uint16_t complementary_code_keying:1;
    uint16_t orthogonal_frequency_division_multiplexing:1;
    uint16_t GHz_spectrum_2:1;
    uint16_t GHz_spectrum_5:1;
    uint16_t passive:1;
    uint16_t dynamic_CCK_OFDM:1;
    uint16_t gaussian_frequency_shift_keying:1;
    uint16_t GSM:1;
    uint16_t static_turbo:1;
    uint16_t half_rate_channel:1;
    uint16_t quarter_rate_channel:1;
    /**************************channel flags******************************/

    uint8_t SSI_signal;
    uint8_t antenna;
    uint16_t RX_flags;
}typedef Channel;

struct IEEE80211{

    /**************************Frame Control Field************************/
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subType:4;



        /**************************Flags**************************************/
    uint8_t DS_status:2;
    uint8_t more_fragments:1;
    uint8_t retry:1;
    uint8_t PWR_MGT:1;
    uint8_t more_data:1;
    uint8_t protected_flag:1;
    uint8_t order_flag:1;
        /**************************Flags**************************************/

    uint16_t duration:15;
    uint16_t padding:1;
    /**************************Frame Control Field************************/

//    uint8_t receiver_address[6]; same as destination address

}typedef IEEE80211;

struct IEEE80211Beacon{

    uint8_t destination_address[6];
   // uint8_t transmitter_address[6]; same as source_address
    uint8_t source_address[6];
    uint8_t BSS_Id[6];

    uint16_t fragment_number:4;
    uint16_t sequence_number:12;
  //  uint16_t frame_check_sequence;


};

struct IEEE80211Data{

    uint8_t destination_address[6];
    uint8_t transmitter_address[6];
    uint8_t source_address[6];
//    uint8_t BSS_Id[6]; //same as transmitter_address
//    uint8_t STA address[6]; //same as destination_address
    uint16_t fragment_number:4;
    uint16_t sequence_number:12;
  //  uint16_t frame_check_sequence;


};

struct IEEE80211Probe{

    uint8_t destination_address[6];
    uint8_t transmitter_address[6];
//    uint8_t source_address[6]; //same as transmitter_address
    uint8_t BSS_Id[6];

    uint16_t fragment_number:4;
    uint16_t sequence_number:12;
  //  uint16_t frame_check_sequence;


};


struct IEEE80211QoS{

    uint8_t receiver_address[6];
    uint8_t transmitter_address[6];
    uint8_t destination_address[6];
//    uint8_t source_address[6]; //same as transmitter_address
//    uint8_t BSS_Id[6]; //same as transmitter_address
//    uint8_t STA address[6]; //same as destination_address
    uint16_t fragment_number:4;
    uint16_t sequence_number:12;
  //  uint16_t frame_check_sequence;


};

struct IEEE80211BlockAck{

    uint8_t receiver_address[6];
    uint8_t transmitter_address[6];

    /********************Block Ack Request Control***********************************/
    uint16_t bar_ack_policy:1;
    uint16_t multi_TID:1;
    uint16_t compressed_bitmap:1;
    uint16_t reserved:9;
    uint16_t tid:4;
    /********************Block Ack Request Control***********************************/

    /********************Block Ack Starting Sequence Control(SSC)********************/
    uint16_t fragment:4;
    uint16_t starting_sequence_number:12;
    uint8_t block_ack_bitmap[8];


};

/************************wireless LAN management frame****************************************/
struct FixedParameters{
    uint8_t timestamp[8];
    uint16_t beaconInterval;

    /******************capabilities Infomaiton************************/
    uint16_t ess_capabilities:1;
    uint16_t ibss_status:1;
    uint16_t cfp_participation_capabilities:2;
    uint16_t privacy:1;
    uint16_t short_preamble:1;
    uint16_t pbcc:1;
    uint16_t channel_agility:1;
    uint16_t spectrum_management:1;
    uint16_t cfp_participation_capabilities2:1;
    uint16_t short_slot_time:1;
    uint16_t automatic_power_save_delivery:1;
    uint16_t radio_masurement:1;
    uint16_t dsss_ofdm:1;
    uint16_t delayed_block_ack:1;
    uint16_t immediate_block_ack:1;
    /******************capabilities Infomaiton************************/
};


struct TagInfo{
    uint8_t tag_number;
    uint8_t tag_length;
};

//SSID parameter size is sizeof(taggedParameters)+tag_length-sizeof(char)
struct SSIDParameter{
    struct TagInfo tagInfo;
    char SSID;
};

struct SupportedRate{
    struct TagInfo tagInfo;
    uint8_t supported_rates[8];
};

struct DSParameter{
    struct TagInfo tagInfo;
    uint8_t current_channel;

};

struct TrafficIndicationMap{
    struct TagInfo tagInfo;
    uint8_t DTIM_count;
    uint8_t DTIM_period;

    /******Bitmap control********/
    uint8_t multicast:1;
    uint8_t bitmap_offset:7;
    /******Bitmap control********/
    uint8_t partial_virtual_bitmap;

};

struct RSNFront{
    struct TagInfo tagInfo;
    uint16_t rsn_version;

    uint8_t group_cipher_suite_oui[3];
    uint8_t group_cipher_suite_type;

    uint16_t pairwise_cipher_suite_count;
}typedef RSNFront;

struct RSNInfomation{

    RSNFront rsnFront;
    uint8_t pairwise_cipher_suite_oui[3];
    uint8_t pairwise_cipher_suite_type;

    uint16_t auth_key_management_suite_count;
    \
    uint8_t auth_key_management_suite_oui[3];
    uint8_t auth_key_management_suite_type;

    /******************** RSN Capabilities**********************/
    uint16_t rsn_pre_auth_capabilities:1;
    uint16_t rsn_no_pairwise_capabilities:1;
    uint16_t rsn_ptksa_replay_counter_capabilities:2;
    uint16_t rsn_gtksa_replay_counter_capabilities:2;
    uint16_t management_frame_protection_required:1;
    uint16_t joint_multi_band_rsna:1;
    uint16_t peerkey_enabled:1;
    uint16_t padding:6;
    /******************** RSN Capabilities**********************/

};

struct RSNInfomation2{

    RSNFront rsnFront;
    uint8_t pairwise_cipher_suite_oui[3];
    uint8_t pairwise_cipher_suite_type;

    uint8_t pairwise_cipher_suite_oui2[3];
    uint8_t pairwise_cipher_suite_type2;

    uint16_t auth_key_management_suite_count;
    \
    uint8_t auth_key_management_suite_oui[3];
    uint8_t auth_key_management_suite_type;

    /******************** RSN Capabilities**********************/
    uint16_t rsn_pre_auth_capabilities:1;
    uint16_t rsn_no_pairwise_capabilities:1;
    uint16_t rsn_ptksa_replay_counter_capabilities:2;
    uint16_t rsn_gtksa_replay_counter_capabilities:2;
    uint16_t management_frame_protection_required:1;
    uint16_t joint_multi_band_rsna:1;
    uint16_t peerkey_enabled:1;
    uint16_t padding:6;
    /******************** RSN Capabilities**********************/

};

struct VendorSpecific{
    struct TagInfo tagInfo;
    uint8_t oui[3];
    uint8_t vender_specific_oui_type;
};

struct MicrosofWPAFront{
    struct VendorSpecific vendorSpecific;
    uint16_t wpa_version;

    uint8_t mulicast_cipher_suite_oui[3];
    uint8_t mulicast_cipher_suite_type;

    uint16_t unicast_cipher_suite_count;
};

struct MicrosofWPA{

    struct MicrosofWPAFront microsofWPAFront;

    uint8_t unicast_cipher_suite_oui[3];
    uint8_t unicast_cipher_suite_type;

    uint16_t auth_key_management_suite_count;

    uint8_t auth_key_management_suite_oui[3];
    uint8_t auth_key_management_suite_type;

}typedef MicrosofWPA;

struct MicrosofWPA_2{

    struct MicrosofWPAFront microsofWPAFront;

    uint8_t unicast_cipher_suite_oui[3];
    uint8_t unicast_cipher_suite_type;

    uint8_t unicast_cipher_suite_oui2[3];
    uint8_t unicast_cipher_suite_type2;


    uint16_t auth_key_management_suite_count;

    uint8_t auth_key_management_suite_oui[3];
    uint8_t auth_key_management_suite_type;

}typedef MicrosofWPA_2;
#pragma pack(pop)

void parseRadiotap();
bool parseIEEE802(uint8_t* packet,uint8_t subtype,uint8_t* typeStruct);
#endif // IEEE802_H
