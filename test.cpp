#include<iostream>
#include"instruction.hpp"
int main(){
    cppp::bytes buf;
    x86::encode::sub::rm_imm<x86::width::W32>(buf,x86::reg::A,1220);
    std::cout.fill('0');
    std::cout.setf(std::ios_base::hex,std::ios_base::basefield);
    for(std::byte b : buf){
        std::cout.width(2);
        std::cout << static_cast<std::uint32_t>(b) << ' ';
    }
    std::cout.flush();
    return 0;
}
