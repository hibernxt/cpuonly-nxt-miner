#include <stdio.h>
#include <time.h>
#include <set>
#include <thread>
#include <list>
#include <iostream>
#include <sstream>
#include <mutex>
#include <iomanip>
#include "picosha.h"
#include "donna.h"
#include "uint256_t.h"
#include "happyhttp.h"
#ifdef __MINGW32__
    #include <winsock2.h>
    #define vsnprintf _vsnprintf
#endif

static std::mutex countMutex;
static std::mutex resultMutex;
static std::mutex statsMutex;
static std::list<std::string> resultList;
static long long unsigned int tryCount = 0;
static unsigned int resultCount = 0;
static unsigned int queuedCount = 0;

void print_array(std::string title, uint8_t* public_key){
      std::ostringstream ss;

      ss << std::hex << std::uppercase << std::setfill( '0' );
      for( size_t i = 0; i<32; ++i ) {
        ss << std::setw( 2 ) << (int)(public_key[i]);
      }

      std::string result = ss.str();
      std::cout << title << ": " << result << std::endl;
}

std::string get_array(uint8_t* public_key){
      std::ostringstream ss;

      ss << std::hex << std::uppercase << std::setfill( '0' );
      for( size_t i = 0; i<32; ++i ) {
        ss << std::setw( 2 ) << (int)(public_key[i]);
      }

      std::string result = ss.str();
      return result;
}

void work()
{
#ifdef __MINGW32__
    WSADATA wsaData;
    WSAStartup(0x202, &wsaData);
#endif
    static const unsigned int tries = 1;

    uint32_t seed32 = static_cast<uint32_t>(time(0)) ^ static_cast<uint32_t>(std::hash<std::thread::id>()(std::this_thread::get_id()));
    srand(seed32);

    // make global vars
    limb pubpoint[5],pubpointz[5], pubpoint_tmp[5], pubpoint_minus_bp[5],pubpoint_minus_bpz[5], bp[5], uno[5], unoz[5], zmone[5];
    limb uno_destroy[5], unoz_destroy[5];
    uint8_t just_one[32]={1};


    // Create random key and random minus one key
    uint8_t e_minus_one[32];
    uint8_t e[32];
    uint256_t starting_privkey;

    for(size_t i = 0; i < 32; i++){
        if(i>0){
            e_minus_one[i] = (rand()*65515) % 256;
            e[i] = e_minus_one[i];

            if(i==31){
                e_minus_one[31] &= 127;
                e_minus_one[31] |= 64;
                e[31] &= 127;
                e[31] |= 64;
            }
        }else{
            e_minus_one[i]=1;
            e[i]=2;
        }
        uint256_t additor;
        additor = e[i];
        additor = additor << (8*i);
        starting_privkey += additor;
    }

    



    uint8_t basepoint[32]={9};
    uint8_t public_key[32];
    uint64_t internal_counter = 0;



    fexpand(bp, basepoint);

    // create basepoint with x,z    
    cmult(uno, unoz, just_one, bp);
   
    // e minus one with x,z
    cmult(pubpoint_minus_bp, pubpoint_minus_bpz, e_minus_one, bp);
    
    // normalize eminusone right now
    crecip(zmone, pubpoint_minus_bpz);
    fmul(pubpoint_minus_bpz, pubpoint_minus_bp, zmone);
   
    // create e with x.z
    cmult(pubpoint, pubpointz, e, bp);


    while( true )
    {
        // Do work
        crecip(zmone, pubpointz);
        fmul(pubpoint_tmp, pubpoint, zmone);    
        fcontract(public_key, pubpoint_tmp);
        memcpy(uno_destroy,uno,sizeof(limb)*5);
        memcpy(unoz_destroy,unoz,sizeof(limb)*5);
        cadd(pubpoint, pubpointz, pubpoint, pubpointz, uno_destroy, unoz_destroy, pubpoint_minus_bpz);
        // Save minus_bpz
        memcpy(pubpoint_minus_bpz,pubpoint_tmp,sizeof(limb)*5);
       
        // check if we got result
        unsigned char hashed[32];
        picosha2::hash256(public_key, public_key+32, hashed, hashed+32);

        unsigned int a = (hashed[0] << 24) | (hashed[1] << 16) | (hashed[2] << 8) | (hashed[3]);
        if((a==0x25c5a207) || (a==0x861fc1a3) || (a==0x65ae467f) || (a==0xba973233) || (a==0x6e01b0b7) || (a==0x28dca32c) || (a==0xf297ad07) || (a==0xed66fe31) || (a==0xba2d6f04) || (a==0xc846bf0c) || (a==0x4fa8cf07) || (a==0x4e6e2b3d) || (a==0x1febd530) || (a==0x780ad9aa) || (a==0xb60166f3) || (a==0xa0860100) || (a==0xe239bdb) || (a==0xe708b03a) || (a==0xb1efa06b) || (a==0xe2ea7edf) || (a==0x1c96882c)){
            
            // Prepare Match
            uint256_t match = starting_privkey;
            match += internal_counter;

            unsigned char net_order[32];
            for(int i=0;i<32;++i){
                net_order[31-i] = match & 0xFF;
                match = match >> 8;
            }

            //print_array("Privkey Netorder",net_order);
            //print_array("Pubkey",public_key);
            //print_array("Hash",hashed);
            resultMutex.lock();
            resultList.push_back(get_array(net_order));
            resultMutex.unlock();


        }

        internal_counter++;

        countMutex.lock();
        tryCount += tries;
        countMutex.unlock();
    }
}
size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
return size * nmemb;
}
int submit_share(const std::string &address, const std::string &result)
{
    int ret = -1;
    
    char* str = (char*)malloc(sizeof(char)*255);
    sprintf(str,"&key=%s&address=%s",result.c_str(),address.c_str());

    
    
    const char* headers[] = 
    {
        "Connection", "close",
        "Content-type", "application/x-www-form-urlencoded",
        "Accept", "text/plain",
        0
    };

    try{
        happyhttp::Connection conn( "54.191.123.177", 80 );
        conn.request( "POST",
                "/push",
                headers,
                (const unsigned char*)str,
                strlen(str) );

        while( conn.outstanding() )
            conn.pump();
         
        ret = 1;
    }
    catch( happyhttp::Wobbly& e )
    {
        fprintf(stderr, "Exception:\n%s\n", e.what() );
    }
    free(str); 
    return ret;
}

void submitter(const std::string btc)
{
    std::list<std::string> queuedResults;
    
    std::chrono::milliseconds sleeptime( 100 );

    while( true )
    {
        resultMutex.lock();
        queuedResults.splice(queuedResults.end(), resultList);
        resultMutex.unlock();
        
        std::list<std::string> heldResults;

        if (queuedResults.size())
        {
            std::string rs(queuedResults.front());
            queuedResults.pop_front();

            int r = submit_share(btc, rs);

            statsMutex.lock();
            switch (r)
            {
            case -1:
                heldResults.push_back(rs);
                break;
            case 1:
                ++ resultCount;
                break;
            }
            queuedCount = static_cast<unsigned int>(queuedResults.size() + heldResults.size());
            statsMutex.unlock();

            queuedResults.splice(queuedResults.end(), heldResults);
        } else {
            std::this_thread::sleep_for( sleeptime );
        }
    }
}

int main(int argc, char **argv)
{
    if ( argc != 3 )
    {
        printf("Usage: %s bitcoinaddress num_threads\n", argv[0]);
        return -1;
    }

    std::string btc(argv[1]);

    int threadcount = atoi(argv[2]);
    if (threadcount < 1 || threadcount > 512)
    {
        puts("Invalid thread count");
        return -1;
    }

    std::list<std::string> held_results;


    printf("Starting %d threads. Hang on to your hats...\n", threadcount);
    printf("Sending payouts to %s\n", btc.data());

    std::list<std::thread *> threads;
    for( int i = 0; i < threadcount; ++ i )
    {
        threads.push_back(new std::thread(work));
    }
    
    threads.push_back(new std::thread(submitter, btc));
    
    std::chrono::milliseconds sleeptime( 100 );

    time_t secs = time(0);
    time_t starttime = time(0);

    while( true )
    {
        std::this_thread::sleep_for( sleeptime );
        time_t curtime = time(0);
        if (curtime > secs + 10)
        {
            secs = curtime;
            
            countMutex.lock();
            long long unsigned int curtries = tryCount;
            tryCount = 0;
            countMutex.unlock();

            statsMutex.lock();
            double resultsPerHour = static_cast<double>(resultCount) / (static_cast<double>(curtime - starttime) / 60.0 / 60.0);

            printf("%llu keys/sec - %u submitted (%.2f / hour) - %u que\n", curtries / 10, resultCount, resultsPerHour, queuedCount);
            statsMutex.unlock();
        }
    }
}
