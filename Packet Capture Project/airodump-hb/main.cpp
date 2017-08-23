#include <iostream>
#include <map>
#include <thread>
#include <iomanip>
#include "jpcaplib.h"
#include "printdata.h"
#include "ieee802.h"
#include "apinfo.h"

using namespace std;
bool mapSearch(map<uint8_t *, APInfo *> &APmap, uint8_t *sourceAddr);
void mapAdd(map<uint8_t *, APInfo *> &APmap, uint8_t* key, APInfo* value);
void mapDel();
void printAPInfo(uint8_t *pAPMap, uint8_t *pIter);
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

    cout.setf(ios::left); //left sort
    cout<<setw(19)<<" BSSID"<<setw(10)<<"Beacons"<<setw(7)<<"#Data"<<setw(3)<<"CH"<<setw(5)<<"ENC"<<setw(9)<<"CIPTHER"<<setw(5)<<"AUTH"<<setw(20)<<"ESSID"<<endl<<endl;
    cout.setf(ios::right);
    map<uint8_t*,APInfo*> APmap;
    map<uint8_t*,APInfo*>::iterator iter;

    bool test;
   // thread t1(printAPInfo,(uint8_t*)&APmap,(uint8_t*)&iter);
    //   t1.join();
    while(test=recvPacket(pcd,&packet,dataLen)) //if recv packet
    {

        Radiotap* radiotap=(Radiotap*)packet;
        if(radiotap->header_length==18)//if has an channel flag
        {
            Channel* channel=(Channel*)(packet+sizeof(Radiotap));
            (void)channel;
        }


        IEEE80211* ieee80211=(IEEE80211*)(packet+radiotap->header_length);

        if(ieee80211->version==0&&ieee80211->type==0&&ieee80211->subType==8) //if not beacon frame
        {

            cout<<(int)ieee80211->subType<<endl;
            IEEE80211Beacon* ieee80211Beacon=(IEEE80211Beacon*)((uint8_t*)ieee80211+sizeof(IEEE80211));
            if(!mapSearch(APmap,ieee80211Beacon->source_address)) //if not searched
                mapAdd(APmap,ieee80211Beacon->source_address,new APInfo);

            /**************parse wireless LAN management frame***************************/
            struct FixedParameters* fixedParameters = (struct FixedParameters*)((uint8_t*)ieee80211Beacon+sizeof(IEEE80211Beacon));
            struct SSIDParameter* ssidParameter=(struct SSIDParameter*)((uint8_t*)fixedParameters+sizeof(FixedParameters));
            struct SupportedRate* supportedRate=(struct SupportedRate*)((uint8_t*)ssidParameter+sizeof(SSIDParameter)-sizeof(char)+ssidParameter->tag_length);
            struct DSParameter* dsParameter=(struct DSParameter*)((uint8_t*)supportedRate+sizeof(SupportedRate));
            struct TrafficIndicationMap* trafficIndicationMap=(struct TrafficIndicationMap*)((uint8_t*)dsParameter+sizeof(DSParameter));
            (void)trafficIndicationMap;

            //set AP info
            iter=APmap.find(ieee80211Beacon->source_address);
            APInfo* apInfo=iter->second;

            apInfo->BSSID=ieee80211Beacon->source_address;
            apInfo->incBeacons();
            apInfo->setChannel(dsParameter->current_channel);

            memcpy(apInfo->ESSID,&ssidParameter->SSID,ssidParameter->tag_length);
            apInfo->ESSID[ssidParameter->tag_length]=0;
            printByHexData(packet,dataLen);
            printAPInfo((uint8_t*)&APmap,(uint8_t*)&iter);

        }

//        threadFlag=true;
    }




    return 0;
}

bool mapSearch(map<uint8_t*,APInfo*>& APmap,uint8_t* sourceAddr)
{

    if(APmap.find(sourceAddr)==APmap.end())
        return false;

    return true;

}

void mapAdd(map<uint8_t*,APInfo*>& APmap,uint8_t* key,APInfo* value)
{
    APmap[key]=value;
}


void printAPInfo(uint8_t* pAPMap,uint8_t* pIter)
{
    map<uint8_t*, APInfo*> *APmap=(map<uint8_t*, APInfo*>*)pAPMap;
    map<uint8_t*,APInfo*>::iterator *iter=(map<uint8_t*,APInfo*>::iterator*)pIter;
//    while(true)
//    {
        for((*iter)=APmap->begin();(*iter)!=APmap->end();(*iter)++)
        {
            APInfo* apInfo=(*iter)->second;
            cout<<" ";
            printByMAC(apInfo->BSSID.macAddr,6);
            cout.setf(ios::left);
            cout<<setw(5)<<" "<<setw(3)<<(int)apInfo->getBeacons()<<setw(8)<<(int)apInfo->getData()<<setw(4)<<(int)apInfo->getChannel()<<setw(5)<<apInfo->enc<<setw(9)<<apInfo->cipher<<setw(5)<<apInfo->auth<<setw(20)<<apInfo->ESSID<<"\n";
            cout.setf(ios::right);
        }
//        threadFlag=false;
//    }
}
