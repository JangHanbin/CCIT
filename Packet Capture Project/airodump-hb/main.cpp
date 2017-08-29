#include <iostream>
#include <map>
#include <iomanip>
#include "stationinfo.h"
#include "jpcaplib.h"
#include "printdata.h"
#include "ieee802.h"
#include "apinfo.h"

using namespace std;


class MapKey{


public:

    uint8_t sourceAddr[6];
    bool operator<(const MapKey& other) const
    {
        return tie(sourceAddr[0],sourceAddr[1],sourceAddr[2],sourceAddr[3],sourceAddr[4],sourceAddr[5])<tie(other.sourceAddr[0],other.sourceAddr[1],other.sourceAddr[2],other.sourceAddr[3],other.sourceAddr[4],other.sourceAddr[5]);
    }


    void operator=(const uint8_t* addr)
    {
        memcpy(sourceAddr,addr,6);
    }

    void printInfo()
    {
        for (int i = 0; i < 6; ++i) {
            cout<<hex<<(int)sourceAddr[i];
        }
        cout<<dec<<endl;
    }
};


bool mapSearch(map<MapKey, APInfo *> &APmap, MapKey &sourceAddr);
void mapAdd(map<MapKey, APInfo *> &APmap, MapKey &key, APInfo* value);
bool mapSearch(map<MapKey, StationInfo *> &StationMap, MapKey &sourceAddr);
void mapAdd(map<MapKey, StationInfo *> &StationMap, MapKey &key, StationInfo* value);
void mapDel();
bool moveNextTag(uint8_t** packet, int &totalTagLen);
void copyCipherInfo(char* cipher, int count, int control, int otherType);
void copyAuthInfo(char* auth, int count, int control, int type);
void printAPInfo(uint8_t *pAPMap, uint8_t *pIter);
void printStationInfo(map<MapKey,StationInfo*>&StationMap, map<MapKey,StationInfo*>::iterator& iterS, int sizeOfAP);
void upLinePrompt(int count);
void usage()
{\
    cout<<"Usage : airodump-hb <Device>"<<endl;
    exit(1);
}

bool checkArgc(int argc)
{
    if(argc!=2)
        usage();

    return true;
}

bool threadFlag=false;


int main(int argc, char *argv[])
{
    char* dev;
    if(checkArgc(argc))
        dev=argv[1];
    pcap_t* pcd=pOpen(dev);

    uint8_t* packet;
    int dataLen;

    uint8_t broadCast[]={0xff,0xff,0xff,0xff,0xff,0xff};

    cout.setf(ios::left); //left sort
    cout<<setw(19)<<" BSSID"<<setw(10)<<"Beacons"<<setw(7)<<"#Data"<<setw(3)<<"CH"<<setw(6)<<" ENC"<<setw(9)<<"  CIPTHER"<<setw(5)<<"  AUTH"<<setw(20)<<" ESSID"<<endl<<endl;
    cout.setf(ios::right);
    map<MapKey,APInfo*> APmap;
    map<MapKey,APInfo*>::iterator iter;

    map<MapKey,StationInfo*> StationMap;
    map<MapKey,StationInfo*>::iterator iterS;

   // thread t1(printAPInfo,(uint8_t*)&APmap,(uint8_t*)&iter);
    //   t1.join();
    while(recvPacket(pcd,&packet,dataLen)) //if recv packet
    {

        Radiotap* radiotap=(Radiotap*)packet;

        /*
        if(radiotap->header_length==36)//if has an channel flag
        {
            Channel* channel=(Channel*)(packet+sizeof(Radiotap));
            (void)channel;
        }
*/


        IEEE80211* ieee80211=(IEEE80211*)(packet+radiotap->header_length);
        dataLen-=radiotap->header_length;

        if(ieee80211->version==0&&ieee80211->type==0&&ieee80211->subType==8) //if beacon frame
        {

            IEEE80211Beacon* ieee80211Beacon=(IEEE80211Beacon*)((uint8_t*)ieee80211+sizeof(IEEE80211));
            dataLen-=sizeof(IEEE80211);

            //make MapKey
            MapKey mapKey;
            mapKey=ieee80211Beacon->source_address;


            if(!mapSearch(APmap,mapKey)) //if not searched
                mapAdd(APmap,mapKey,new APInfo);

            //set AP info
            iter=APmap.find(mapKey);
            APInfo* apInfo=iter->second;

            apInfo->BSSID=ieee80211Beacon->source_address;


            /**************parse wireless LAN management frame***************************/
            struct FixedParameters* fixedParameters = (struct FixedParameters*)((uint8_t*)ieee80211Beacon+sizeof(IEEE80211Beacon));
            dataLen-=sizeof(IEEE80211Beacon);

            if(!fixedParameters->privacy)
                strcpy(apInfo->enc,"OPN ");

            /**************parse tagged parameters***************************************/
            uint8_t* taggedPointer=(uint8_t*)fixedParameters+sizeof(FixedParameters);
            dataLen-=sizeof(FixedParameters);
            if(radiotap->FCS_at_end)
                dataLen-=4; //except checksum

            do{
                struct TagInfo* tagInfo=(struct TagInfo*)taggedPointer;
                switch (tagInfo->tag_number)
                {
                case 0: //SSID parameter Set
                    {
                        SSIDParameter* ssidParameter=(SSIDParameter*)taggedPointer;
                        apInfo->setEssidLen(ssidParameter->tagInfo.tag_length);
                        memcpy(apInfo->ESSID,&ssidParameter->SSID,apInfo->getEssidLen());

                        break;
                    }
                case 3: //DS parameter set
                    {
                        DSParameter* dsParameter=(DSParameter*)taggedPointer;
                        apInfo->setChannel(dsParameter->current_channel);
                        break;
                    }
                case 48:
                    {
                        RSNFront* rsnFront=(RSNFront*)taggedPointer;

                        strcpy(apInfo->enc,"WPA2");
                        if(rsnFront->pairwise_cipher_suite_count==1)
                        {
                            RSNInfomation* rsnInfomation=(RSNInfomation*)taggedPointer;

                            if(memcmp(rsnInfomation->pairwise_cipher_suite_oui,ieeeOUI,3)==0) //if 00-of-ac(IEEEOUI)
                                copyCipherInfo(apInfo->cipher,rsnFront->pairwise_cipher_suite_count,rsnInfomation->pairwise_cipher_suite_type,-1);

                            if(memcmp(rsnInfomation->auth_key_management_suite_oui,ieeeOUI,3)==0)
                                copyAuthInfo(apInfo->auth,rsnInfomation->auth_key_management_suite_count,rsnInfomation->auth_key_management_suite_type,1); //type 1 = WPA2 type 2 = WPA

                        }else if(rsnFront->pairwise_cipher_suite_count==2)
                        {
                            RSNInfomation2* rsnInfomation2=(RSNInfomation2*)taggedPointer;

                            if(memcmp(rsnInfomation2->pairwise_cipher_suite_oui,ieeeOUI,3)==0&&memcmp(rsnInfomation2->pairwise_cipher_suite_oui2,ieeeOUI,3)==0) //if 00-of-ac(IEEEOUI)
                                copyCipherInfo(apInfo->cipher,rsnFront->pairwise_cipher_suite_count,rsnInfomation2->pairwise_cipher_suite_type,rsnInfomation2->pairwise_cipher_suite_type2);

                            if(memcmp(rsnInfomation2->auth_key_management_suite_oui,ieeeOUI,3)==0)
                                copyAuthInfo(apInfo->auth,rsnInfomation2->auth_key_management_suite_count,rsnInfomation2->auth_key_management_suite_type,1);
                        }
                        break;
                    }
                case 221: //vender specific
                {
                    struct VendorSpecific* vendorSpecific=(struct VendorSpecific*)taggedPointer;
                    if(memcmp(vendorSpecific->oui,microsof,3)==0)
                            if(vendorSpecific->vender_specific_oui_type==1)
                            {
                                strcpy(apInfo->enc,"WPA");
                                struct MicrosofWPAFront* microsofWPAFront=(struct MicrosofWPAFront*)taggedPointer;
                                if(microsofWPAFront->unicast_cipher_suite_count==1)
                                {
                                    MicrosofWPA* microsofWPA=(MicrosofWPA*)taggedPointer;

                                    if(memcmp(microsofWPA->unicast_cipher_suite_oui,microsof,3)==0)
                                        copyCipherInfo(apInfo->cipher,microsofWPA->microsofWPAFront.unicast_cipher_suite_count,microsofWPA->unicast_cipher_suite_type,-1);

                                    if(memcmp(microsofWPA->auth_key_management_suite_oui,microsof,3)==0)
                                        copyAuthInfo(apInfo->auth,microsofWPA->auth_key_management_suite_count,microsofWPA->auth_key_management_suite_type,2);


                                }else if(microsofWPAFront->unicast_cipher_suite_count==2)
                                {
                                    MicrosofWPA_2* microsofWPA_2=(MicrosofWPA_2*)taggedPointer;

                                    if(memcmp(microsofWPA_2->unicast_cipher_suite_oui,microsof,3)==0)
                                        copyCipherInfo(apInfo->cipher,microsofWPA_2->microsofWPAFront.unicast_cipher_suite_count,microsofWPA_2->unicast_cipher_suite_type,microsofWPA_2->unicast_cipher_suite_type2);

                                    if(memcmp(microsofWPA_2->auth_key_management_suite_oui,microsof,3)==0)
                                        copyAuthInfo(apInfo->auth,microsofWPA_2->auth_key_management_suite_count,microsofWPA_2->auth_key_management_suite_type,2);
                                }


                            }

                    break;
                }
                default:
                    break;
                }
            }while (moveNextTag(&taggedPointer,dataLen));


            /**************parse wireless LAN management frame***************************/





            apInfo->incBeacons();
            printAPInfo((uint8_t*)&APmap,(uint8_t*)&iter);
            printStationInfo(StationMap,iterS,APmap.size());



        }else if(ieee80211->version==0&&ieee80211->type==2&&ieee80211->subType==0)// if data frame
        {
            IEEE80211Data* ieee80211Data=(IEEE80211Data*)((uint8_t*)ieee80211+sizeof(IEEE80211));

            //make MapKey
            MapKey mapKey;
            mapKey=ieee80211Data->transmitter_address;

            if(mapSearch(APmap,mapKey)) //if searched (transmitter is BSSID)
            {
                //set AP info
                iter=APmap.find(mapKey);
                APInfo* apInfo=iter->second;

                apInfo->incData();

                /*******************Add Station************************/
                MapKey mapKeyS;
                mapKeyS=ieee80211Data->source_address; //change key

                if((!mapSearch(StationMap,mapKeyS))&&(!mapSearch(APmap,mapKeyS))) //if not found && mapKey is not AP BSSID
                    mapAdd(StationMap,mapKeyS,new StationInfo);


                //modified !mapSearch(APmap,mapKeyS)
                if(mapSearch(StationMap,mapKeyS)) //if already exist station or just added
                {
                    iterS=StationMap.find(mapKeyS);
                    StationInfo* stationInfo=iterS->second;
                    stationInfo->incFrames();
                    stationInfo->BSSID=ieee80211Data->transmitter_address;
                    stationInfo->station=ieee80211Data->source_address;
                    memcpy(stationInfo->ESSID,apInfo->ESSID,apInfo->getEssidLen()+1);//+1 ==null

                }
                printAPInfo((uint8_t*)&APmap,(uint8_t*)&iter);
                printStationInfo(StationMap,iterS,APmap.size());
            }


        }else if(ieee80211->version==0&&ieee80211->type==0&&(ieee80211->subType==5||ieee80211->subType==4)) //if probe frame
        {
             IEEE80211Probe* ieee80211Probe=(IEEE80211Probe*)((uint8_t*)ieee80211+sizeof(IEEE80211));

             //make MapKey
             MapKey mapKeyS;
             mapKeyS=ieee80211Probe->transmitter_address;


             if((!mapSearch(StationMap,mapKeyS))&&(!mapSearch(APmap,mapKeyS))&&ieee80211->subType==4) //if not found && mapKey is not AP BSSID && Probe Request
                 mapAdd(StationMap,mapKeyS,new StationInfo);

             if(mapSearch(StationMap,mapKeyS)&&ieee80211->subType==4) //if searched (source_address is station) &&
             {
                 SSIDParameter *ssidParameter=(struct SSIDParameter*)((uint8_t*)ieee80211Probe+sizeof(IEEE80211Probe));
                 //set StationInfo
                 iterS=StationMap.find(mapKeyS);
                 StationInfo *stationInfo=iterS->second;

                 stationInfo->station=ieee80211Probe->transmitter_address;
                 stationInfo->setEssidLen(ssidParameter->tagInfo.tag_length);
                 stationInfo->BSSID=ieee80211Probe->destination_address; //BSSID saved by broadCast

                 if(stationInfo->getEssidLen()!=0) //there is no SSID
                 {
                     memcpy(stationInfo->ESSID,&ssidParameter->SSID,stationInfo->getEssidLen());
                 }


                stationInfo->incFrames();

             }

             printAPInfo((uint8_t*)&APmap,(uint8_t*)&iter);
             printStationInfo(StationMap,iterS,APmap.size());

        }else if(ieee80211->version==0&&ieee80211->type==2&&ieee80211->subType==8) //if Qos Frame
        {
            IEEE80211QoS* ieee80211QoS=(IEEE80211QoS*)((uint8_t*)ieee80211+sizeof(IEEE80211));

            //make MapKey
            MapKey mapKey;
            mapKey=ieee80211QoS->transmitter_address;
            MapKey& mapKeyS=mapKey;

            if(ieee80211->DS_status==1)//if station to AP
            {
                if(!mapSearch(StationMap,mapKeyS)&&!mapSearch(APmap,mapKey)) //if not found && is not AP BSSID
                    mapAdd(StationMap,mapKeyS,new StationInfo);

                if(mapSearch(StationMap,mapKeyS))
                {
                    iterS=StationMap.find(mapKeyS);
                    StationInfo* stationInfo=iterS->second;

                    stationInfo->BSSID=ieee80211QoS->destination_address;
                    stationInfo->station=ieee80211QoS->transmitter_address;

                    stationInfo->incFrames();

                }

            }
            if(ieee80211->DS_status==2)//if AP to station
            {
                if(!mapSearch(APmap,mapKey)&&!mapSearch(StationMap,mapKeyS)) //if not found && is not AP BSSID
                    mapAdd(APmap,mapKey,new APInfo);

                if(mapSearch(APmap,mapKey))
                {
                    //set AP info
                    iter=APmap.find(mapKey);
                    APInfo* apInfo=iter->second;

                    /*********************need to modify********************************/
                    apInfo->incData();

                }
            }

            printAPInfo((uint8_t*)&APmap,(uint8_t*)&iter);
            printStationInfo(StationMap,iterS,APmap.size());

        }else if(ieee80211->version==0&&ieee80211->type==1&&ieee80211->subType==9) //if Block Ack frame
        {
            IEEE80211BlockAck *ieee80211BlockAck=(IEEE80211BlockAck*)((uint8_t*)ieee80211+sizeof(IEEE80211));

            MapKey mapKeyS;
            mapKeyS=ieee80211BlockAck->receiver_address;

            if(!mapSearch(StationMap,mapKeyS)&&!(mapSearch(APmap,mapKeyS)))
                mapAdd(StationMap,mapKeyS,new StationInfo);


            if(mapSearch(StationMap,mapKeyS))
            {
                //set Station info
                iterS=StationMap.find(mapKeyS);
                StationInfo* stationInfo=iterS->second;

                stationInfo->station=ieee80211BlockAck->receiver_address;
                stationInfo->BSSID=ieee80211BlockAck->transmitter_address;

                stationInfo->incFrames();

            }
            printAPInfo((uint8_t*)&APmap,(uint8_t*)&iter);
            printStationInfo(StationMap,iterS,APmap.size());


        }

    }




    return 0;
}

bool mapSearch(map<MapKey,APInfo*>& APmap,MapKey& sourceAddr)
{

    if(APmap.find(sourceAddr)!=APmap.end())
        return true;

    return false;

}

void mapAdd(map<MapKey,APInfo*>& APmap,MapKey& key,APInfo* value)
{
    APmap.insert(pair<MapKey,APInfo*>(key,value));
}

bool mapSearch(map<MapKey,StationInfo*>& StationMap,MapKey& sourceAddr)
{

    if(StationMap.find(sourceAddr)!=StationMap.end())
        return true;

    return false;

}

void mapAdd(map<MapKey,StationInfo*>& StationMap,MapKey& key,StationInfo* value)
{
    StationMap.insert(pair<MapKey,StationInfo*>(key,value));
}

bool moveNextTag(uint8_t **packet, int &totalTagLen)
{
    struct TagInfo* tagInfo=(struct TagInfo*)(*packet);

    int size=sizeof(struct TagInfo)+tagInfo->tag_length;
    if(totalTagLen-size<=0)
    {
        return false;
    }
    else
    {
        totalTagLen-=size;
        *packet=*packet+size;
        return true;
    }
}

void copyCipherInfo(char *cipher, int count, int control,int otherType)
{
    if(count==1)
    {
        switch (control)
        {
        case 2:
            strcpy(cipher,"TKIP");
            break;
        case 4:
            strcpy(cipher,"CCMP");
            break;

        default:
            break;
        }
    }else if(count==2)
    {
        //find ENC & Cipher
        switch (control)
        {
        case 2:
            if(otherType==4)
                strcpy(cipher,"TKIP+CCMP");
            else
                strcpy(cipher,"TKIP");

            break;
        case 4:
            if(otherType==2)
                strcpy(cipher,"TKIP+CCMP");
            else
                strcpy(cipher,"CCMP");

            break;

        default:
            break;
        }
    }
}

void copyAuthInfo(char* auth,int count,int control,int type)
{
    if(type==1&&count==1)
    {
        switch (control)
        {
        case 1:
            strcpy(auth,"802.1X");
            break;
        case 2:
            strcpy(auth,"CCMP");
            break;
        default:
            break;
        }
    }else if(type==2&&count==1)
    {
        switch (control)
        {
        case 1:
            strcpy(auth,"802.1X");
            break;
        case 2:
            strcpy(auth,"PSK");
            break;
        default:
            break;
        }
    }


}

void printAPInfo(uint8_t* pAPMap,uint8_t* pIter)
{
    map<MapKey, APInfo*> *APmap=(map<MapKey, APInfo*>*)pAPMap;
    map<MapKey,APInfo*>::iterator *iter=(map<MapKey,APInfo*>::iterator*)pIter;

    int size;
    cout.setf(ios::left);
    for((*iter)=APmap->begin();(*iter)!=APmap->end();(*iter)++)
    {
        size=APmap->size();
        APInfo* apInfo=(*iter)->second;
        cout<<" ";
        printByMAC(apInfo->BSSID.macAddr,6);

        cout<<setw(5)<<" "<<setw(3)<<(int)apInfo->getBeacons()<<setw(8)<<(int)apInfo->getData()<<setw(4)<<(int)apInfo->getChannel();

        cout.setf(ios::right);
        setfill('0');
        cout<<setw(6)<<apInfo->enc<<setw(10)<<apInfo->cipher<<setw(6)<<apInfo->auth<<" "<<apInfo->ESSID<<setw(5)<<" ";

        //print control
        if(size-->0)
            cout<<endl;
        else
            cout<<"\r";

    }
    cout.setf(ios::right);



}

void printStationInfo(map<MapKey, StationInfo *> &StationMap, map<MapKey,StationInfo*>::iterator &iterS,int sizeOfAP)
{
    for(int i=0;i<8-sizeOfAP;i++)
        cout<<endl;
    cout.setf(ios::left);
    cout<<" BSSID"<<setw(25)<<"STATION"<<setw(10)<<" "<<setw(10)<<"Frames"<<setw(10)<<"Probe"<<endl;


    int size=StationMap.size();
    for (iterS = StationMap.begin(); iterS!=StationMap.end();iterS++)
    {
        StationInfo *stationInfo=iterS->second;
        cout<<" ";
        printByMAC(stationInfo->BSSID.macAddr,6);
        cout<<setw(5)<<" ";
        cout<<" ";
        printByMAC(stationInfo->station.macAddr,6);
        cout<<setw(2)<<" ";
        cout.setf(ios::right);
        cout<<setw(8)<<stationInfo->getFrames();
//        cout.setf(ios::left);
        cout<<setw(5)<<" "<<stationInfo->ESSID;
        if(size-->0)
            cout<<endl;
        else
            cout<<"\r";

    }

    upLinePrompt(sizeOfAP+StationMap.size()+1+(8-sizeOfAP)); //1 is Station List Info
    cout.setf(ios::right);
}

void upLinePrompt(int count)
{
    for (int i = 0; i < count; ++i) {
        //printf("%c[2K",27);
        cout<<"\33[2K"; //line clear
        cout<<"\x1b[A"; //up line (ESC [ A) must be support VT100 escape seq
    }
}
