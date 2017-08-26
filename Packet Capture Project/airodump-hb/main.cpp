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
    cout<<setw(19)<<" BSSID"<<setw(10)<<"Beacons"<<setw(7)<<"#Data"<<setw(3)<<"CH"<<setw(5)<<"ENC"<<setw(9)<<"CIPTHER"<<setw(5)<<"AUTH"<<setw(20)<<"ESSID"<<endl<<endl;
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
        if(radiotap->header_length==18)//if has an channel flag
        {
            Channel* channel=(Channel*)(packet+sizeof(Radiotap));
            (void)channel;
        }


        IEEE80211* ieee80211=(IEEE80211*)(packet+radiotap->header_length);

        if(ieee80211->version==0&&ieee80211->type==0&&ieee80211->subType==8) //if beacon frame
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
            /**************parse wireless LAN management frame***************************/


            //set AP info
            iter=APmap.find(mapKey);
            APInfo* apInfo=iter->second;

            apInfo->BSSID=ieee80211Beacon->source_address;
            apInfo->incBeacons();
            apInfo->setChannel(dsParameter->current_channel);
            apInfo->setEssidLen(ssidParameter->tag_length);
            memcpy(apInfo->ESSID,&ssidParameter->SSID,apInfo->getEssidLen());
            apInfo->ESSID[ssidParameter->tag_length]=0;
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
                 stationInfo->setEssidLen(ssidParameter->tag_length);
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

        cout<<setw(5)<<" "<<setw(3)<<(int)apInfo->getBeacons()<<setw(8)<<(int)apInfo->getData()<<setw(4)<<(int)apInfo->getChannel()<<setw(5)<<apInfo->enc<<setw(9)<<apInfo->cipher;
        cout.setf(ios::right);
        cout<<setw(5)<<apInfo->auth<<" "<<apInfo->ESSID<<setw(5)<<" ";

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
//    upLinePrompt(sizeOfAP+StationMap.size()+2); //3 is cout<<endl<<endl; + Station List Info
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
