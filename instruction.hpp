#pragma once
#include"common.hpp"
#include<cppp/bytearray.hpp>
#include<type_traits>
#include<utility>
#include<cstdint>
#include<bit>
namespace x86{
    using namespace asm_generic;
    using cppp::bytes;
    enum class width{
        BYTE = 8, WORD = 16, DWORD = 32, QWORD = 64,
        W8 = 8, W16 = 16, W32 = 32, W64 = 64
    };
    enum class scale : std::uint8_t{
        S1 = 0, S2 = 1, S4 = 2, S8 = 3
    };
    namespace{
        template<width w>
        using wvx = std::conditional_t<
            w == width::BYTE,
            std::uint8_t,
            std::conditional_t<
                w == width::WORD,
                std::uint16_t,
                std::uint32_t
            >
        >;
        template<width w>
        using wv = std::conditional_t<
            w == width::QWORD,
            std::uint64_t,
            wvx<w>
        >;
    }
    namespace rex{
        constexpr inline std::byte REX = 0b01000000_b;
        constexpr inline std::byte W = 0b00001000_b;
        constexpr inline std::byte R = 0b00000100_b;
        constexpr inline std::byte X = 0b00000010_b;
        constexpr inline std::byte B = 0b00000001_b;
    }
    namespace regv{
        constexpr inline std::byte A = 0_b;
        constexpr inline std::byte C = 1_b;
        constexpr inline std::byte D = 2_b;
        constexpr inline std::byte B = 3_b;
        constexpr inline std::byte SP = 4_b;
        constexpr inline std::byte BP = 5_b;
        constexpr inline std::byte SI = 6_b;
        constexpr inline std::byte DI = 7_b;
        constexpr inline std::byte AH = 4_b;
        constexpr inline std::byte BH = 5_b;
        constexpr inline std::byte CH = 6_b;
        constexpr inline std::byte DH = 7_b;
        template<std::uint32_t ordinal> requires(ordinal < 8)
        inline std::byte XMM = static_cast<std::byte>(ordinal);
    }
    class Reg{
        std::byte _value;
        public:
            constexpr explicit Reg(std::byte value) : _value(value){}
            constexpr std::byte value() const{
                return _value;
            }
    };
    namespace reg{
        constexpr inline Reg A{regv::A};
        constexpr inline Reg C{regv::C};
        constexpr inline Reg D{regv::D};
        constexpr inline Reg B{regv::B};
        constexpr inline Reg SP{regv::SP};
        constexpr inline Reg BP{regv::BP};
        constexpr inline Reg SI{regv::SI};
        constexpr inline Reg DI{regv::DI};
    }
    class RM{
        std::byte pat;
        constexpr RM(std::byte pat) : pat(pat){}
        public:
            constexpr RM(Reg r) : pat(r.value()){}
            constexpr static RM reg(std::byte reg){
                return {0b1100'0000_b | reg};
            }
            // not SP or BP
            constexpr static RM mem(std::byte reg){
                return {reg};
            }
            constexpr std::byte encode(std::byte reg) const{
                return pat | (reg << 3);
            }
    };
    template<width disp> requires(disp == width::W8 || disp == width::W32)
    class DisplacementRM{
        std::byte pat;
        public:
            constexpr DisplacementRM(Reg rmreg) : pat((disp == width::W8 ? 0b0100'0000_b : 0b1000'0000_b) | rmreg.value()){}
            constexpr std::byte encode(std::byte reg){
                return pat | (reg << 3);
            }
    };
    class SIB{
        std::byte pat;
        constexpr SIB(std::byte pat) : pat(pat){}
        public:
            constexpr static SIB b(std::byte base){
                return {0b0010'0000_b | base};
            }
            template<scale scl>
            constexpr static SIB sib(std::byte base,std::byte index){
                return {static_cast<std::byte>(scl) | (index << 3) | base};
            }
            constexpr std::byte encode() const{
                return pat;
            }
    };
    template<width disw,bool rel_bp> requires((disw == width::W8 && !rel_bp) || disw == width::W32)
    class DisplacementSIB{
        std::byte pat;
        constexpr DisplacementSIB(std::byte pat) : pat(pat){}
        public:
            constexpr static DisplacementSIB disp(){
                return {(disw == width::W8 ? 0b0110'0101_b : (rel_bp ? 0b1010'0101_b : 0b0010'0101_b))};
            }
            template<scale scl>
            constexpr static DisplacementSIB sid(std::byte index){
                return {(disw == width::W8 ? 0b0100'0101_b : (rel_bp ? 0b1000'0101_b : 0b0000'0101_b)) | (index << 3)};
            }
            constexpr std::byte encode() const{
                return pat;
            }
    };
    namespace encode{
        namespace _detail{
            template<std::byte basec,width w>
            void e_op_rm(bytes& buf,std::byte rmpat){
                if constexpr(w == width::W64){
                    buf.append(rex::REX | rex::W);
                }
                if constexpr(w == width::W8){
                    buf.append(basec);
                }else{
                    buf.append(static_cast<std::byte>(static_cast<std::uint8_t>(basec)+1));
                }
                buf.append(rmpat);
            }
            template<std::byte basec,std::byte reg>
            struct i_rm{
                template<width w>
                static void rm(bytes& buf,RM rm){
                    e_op_rm<basec,w>(buf,rm.encode(reg));
                }
                template<width w,width disw>
                static void rm(bytes& buf,DisplacementRM<disw> rm,wv<disw> disp){
                    e_op_rm<basec,w>(buf,rm.encode(reg));
                    buf.appendl(disp);
                }
                template<width w>
                static void rm(bytes& buf,SIB sib){
                    e_op_rm<basec,w>(buf,RM::mem(0b100_b).encode(reg));
                }
                template<width w,width disw>
                static void rm(bytes& buf,SIB sib,wv<disw> disp){
                    e_op_rm<basec,w>(buf,DisplacementRM<disw>(0b100_b).encode(reg));
                    buf.append(sib.encode());
                }
            };
            template<std::byte basec,std::byte reg>
            struct i_rm_imm{
                template<width w>
                static void rm_imm(bytes& buf,RM rm,wvx<w> imm){
                    i_rm<basec,reg>::template rm<w>(buf,rm);
                    buf.appendl(imm);
                }
                template<width w,width disw>
                static void rm_imm(bytes& buf,DisplacementRM<disw> rm,wvx<w> imm,wv<disw> disp){
                    i_rm<basec,reg>::template rm<w>(buf,rm,disp);
                    buf.appendl(imm);
                }
                template<width w>
                static void rm_imm(bytes& buf,SIB sib,wvx<w> imm){
                    i_rm<basec,reg>::template rm<w>(buf,sib);
                    buf.appendl(imm);
                }
                template<width w,width disw,bool rel_bp>
                static void rm_imm(bytes& buf,DisplacementSIB<disw,rel_bp> sib,wvx<w> imm,wv<disw> disp){
                    i_rm<basec,reg>::template rm<w>(buf,sib,disp);
                    buf.appendl(imm);
                }
            };
            template<std::byte basec>
            struct i_rm_r{
                template<width w>
                static void rm_r(bytes& buf,RM rm,Reg reg){
                    e_op_rm<basec,w>(buf,rm.encode(reg.value()));
                }
                template<width w,width disw>
                static void rm_r(bytes& buf,DisplacementRM<disw> rm,wv<disw> disp,Reg reg){
                    e_op_rm<basec,w>(buf,rm.encode(reg.value()));
                    buf.appendl(disp);
                }
                template<width w>
                static void rm_r(bytes& buf,SIB sib,Reg reg){
                    e_op_rm<basec,w>(buf,RM::mem(0b100_b).encode(reg.value()));
                }
                template<width w,width disw>
                static void rm_r(bytes& buf,SIB sib,wv<disw> disp,Reg reg){
                    e_op_rm<basec,w>(buf,DisplacementRM<disw>(0b100_b).encode(reg.value()));
                    buf.append(sib.encode());
                }
            };
            template<std::byte basec>
            struct i_r_rm{
                template<width w>
                static void r_rm(bytes& buf,Reg reg,RM rm){
                    i_rm_r<basec>::template rm_r<w>(buf,rm,reg);
                }
                template<width w,width disw>
                static void r_rm(bytes& buf,Reg reg,DisplacementRM<disw> rm,wv<disw> disp){
                    i_rm_r<basec>::template rm_r<w,disw>(buf,rm,disp,reg);
                }
                template<width w>
                static void r_rm(bytes& buf,Reg reg,SIB sib){
                    i_rm_r<basec>::template rm_r<w>(buf,sib,reg);
                }
                template<width w,width disw>
                static void r_rm(bytes& buf,Reg reg,SIB sib,wv<disw> disp){
                    i_rm_r<basec>::template rm_r<w,disw>(buf,sib,disp,reg);
                }
            };
        }
        struct sub : _detail::i_rm_imm<0x80_b,5_b>, _detail::i_rm_r<0x28_b>{};
        struct add : _detail::i_rm_imm<0x80_b,0_b>, _detail::i_rm_r<0x02_b>{};
        struct mov : _detail::i_rm_imm<0xC6_b,0_b>, _detail::i_rm_r<0x88_b>, _detail::i_r_rm<0x8A_b>{};
        struct ret{
            constexpr static void near(bytes& buf){
                buf.append(0xC3_b);
            }
            constexpr static void far(bytes& buf){
                buf.append(0xCB_b);
            }
        };
    }
}
