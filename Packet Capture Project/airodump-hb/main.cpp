#include <iostream>
#include <map>
#include <thread>
#include <iomanip>
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
    map<MapKey,APInfo*> APmap;
    map<MapKey,APInfo*>::iterator iter;

   // thread t1(printAPInfo,(uint8_t*)&APmap,(uint8_t*)&iter);
    //   t1.join();
    while(recvPacket(pcd,&packet,dataLen)) //if recv packet
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

            IEEE80211Beacon* ieee80211Beacon=(IEEE80211Beacon*)((uint8_t*)ieee80211+sizeof(IEEE80211));

            //make MapKey
            MapKey mapKey;
            mapKey=ieee80211Beacon->source_address;


            if(!mapSearch(APmap,mapKey)) //if not searched
                mapAdd(APmap,mapKey,new APInfo);

            /**************parse wireless LAN management frame***************************/
            struct FixedParameters* fixedParameters = (struct FixedParameters*)((uint8_t*)ieee80211Beacon+sizeof(IEEE80211Beacon));
            struct SSIDParameter* ssidParameter=(struct SSIDParameter*)((uint8_t*)fixedParameters+sizeof(FixedParameters));
            struct SupportedRate* supportedRate=(struct SupportedRate*)((uint8_t*)ssidParameter+sizeof(SSIDParameter)-sizeof(char)+ssidParameter->tag_length);
            struct DSParameter* dsParameter=(struct DSParameter*)((uint8_t*)supportedRate+sizeof(SupportedRate));
            struct TrafficIndicationMap* trafficIndicationMap=(struct TrafficIndicationMap*)((uint8_t*)dsParameter+sizeof(DSParameter));
            (void)trafficIndicationMap;

            //set AP info

            iter=APmap.find(mapKey);
            APInfo* apInfo=iter->second;

            apInfo->BSSID=ieee80211Beacon->source_address;
            apInfo->incBeacons();
            apInfo->setChannel(dsParameter->current_channel);

            memcpy(apInfo->ESSID,&ssidParameter->SSID,ssidParameter->tag_length);
            apInfo->ESSID[ssidParameter->tag_length]=0;
            printAPInfo((uint8_t*)&APmap,(uint8_t*)&iter);

        }

//        threadFlag=true;
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


void printAPInfo(uint8_t* pAPMap,uint8_t* pIter)
{
    map<MapKey, APInfo*> *APmap=(map<MapKey, APInfo*>*)pAPMap;
    map<MapKey,APInfo*>::iterator *iter=(map<MapKey,APInfo*>::iterator*)pIter;

    int size;
//    while(true)
//    {
        for((*iter)=APmap->begin();(*iter)!=APmap->end();(*iter)++)
        {
            size=APmap->size();
            APInfo* apInfo=(*iter)->second;
            cout<<" ";
            printByMAC(apInfo->BSSID.macAddr,6);
            cout.setf(ios::left);
            cout<<setw(5)<<" "<<setw(3)<<(int)apInfo->getBeacons()<<setw(8)<<(int)apInfo->getData()<<setw(4)<<(int)apInfo->getChannel()<<setw(5)<<apInfo->enc<<setw(9)<<apInfo->cipher<<setw(5)<<apInfo->auth<<setw(20)<<apInfo->ESSID;
            if(size-->0)
                cout<<endl;
            else
                cout<<"\r";
            cout.setf(ios::right);

        }

        for (int i = 0; i < APmap->size(); ++i) {
            cout<<"\x1b[A"; //up line (ESC [ A) must be support VT100 escape seq
        }
//        threadFlag=false;
//    }
}
