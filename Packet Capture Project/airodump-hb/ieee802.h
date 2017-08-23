#ifndef IEEE802_H
#define IEEE802_H

#include <iostream>

#pragma pack(push,1)

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
struct FixedParameters{
    uint8_t timestamp[8];
    uint16_t beaconInterval;
    uint16_t capabilitiesInfomation; //need to modify
};

//SSID parameter size is sizeof(taggedParameters)+tag_length-sizeof(char)
struct SSIDParameter{
    uint8_t tag_number;
    uint8_t tag_length;
    char SSID;
};

struct SupportedRate{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t supported_rates[8];
};

struct DSParameter{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t current_channel;

};

struct TrafficIndicationMap{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t DTIM_count;
    uint8_t DTIM_period;

    /******Bitmap control********/
    uint8_t multicast:1;
    uint8_t bitmap_offset:7;
    /******Bitmap control********/
    uint8_t partial_virtual_bitmap;

};

#pragma pack(pop)

void parseRadiotap();
bool parseIEEE802(uint8_t* packet,uint8_t subtype,uint8_t* typeStruct);
#endif // IEEE802_H
