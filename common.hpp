#pragma once
#include<cstddef>
namespace asm_generic{
    consteval inline std::byte operator ""_b(unsigned long long x){
        return static_cast<std::byte>(x);
    }
}
