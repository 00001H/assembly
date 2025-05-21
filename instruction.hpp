#pragma once
#include"common.hpp"
#include<cppp/bytearray.hpp>
#include<type_traits>
#include<algorithm>
#include<stdexcept>
#include<cstdint>
namespace x86{
    using namespace asm_generic;
    using cppp::bytes;
    enum class width{
        BYTE = 0, WORD = 1, DWORD = 2, QWORD = 3,
        W8 = 0, W16 = 1, W32 = 2, W64 = 3
    };
    constexpr inline std::uint32_t width_to_byte_count(width w){
        return w==width::W8?1:w==width::W16?2:w==width::W32?4:8;
    }
    constexpr inline std::byte pack_width(width w){
        return w==width::W8?0_b:w==width::W16?1_b:w==width::W32?2_b:3_b;
    }
    constexpr inline width unpack_width(std::byte b){
        [[assume(b==0_b||b==1_b||b==2_b||b==3_b)]];
        return b==0_b?width::W8:b==1_b?width::W16:b==2_b?width::W32:width::W64;
    }
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
    namespace reg{
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
    class InstructionEncoding{
        // 0000 000i WWwd mpoo
        // 0: unused
        // i: presence of immediate
        // I: width of immediate
        // W: default width (0 = 8, 1 = 16, 2 = 32, 3 = 64)
        // w: instruction width follows destination value
        // d: ModR/M byte denotes destination value
        // m: presence of ModR/M byte
        // p: whether there is a mandatory prefix
        // o: length of opcode
        // 1-4: group 1-4 prefixes
        std::uint16_t _flags;
        std::byte prefix;
        std::byte default_opr;
        std::byte _opcode[3]{0_b};
        public:
            consteval InstructionEncoding(width w,std::optional<std::byte> prefix,std::initializer_list<std::byte> opcode,bool modrm,bool modrm_for_dst,bool sized_with_dst,std::byte opr,bool imm) : _flags(
                (static_cast<std::uint8_t>(imm) << 8)
               |(static_cast<std::uint8_t>(pack_width(w)) << 6)
               |(static_cast<std::uint8_t>(sized_with_dst) << 5)
               |(static_cast<std::uint8_t>(modrm_for_dst) << 4)
               |(static_cast<std::uint8_t>(modrm) << 3)
               |(static_cast<std::uint8_t>(prefix.has_value()) << 2)
               |(static_cast<std::uint8_t>(opcode.size()))
            ), prefix(prefix.value_or(0_b)), default_opr(opr){
                std::ranges::copy(opcode,_opcode);
            }
            bool modrm_is_dst() const{
                return _flags & 0b0001'0000;
            }
            bool dst_size_as_width() const{
                return _flags & 0b0010'0000;
            }
            bool has_immediate() const{
                return _flags & 0b0001'0000'0000;
            }
            bool has_modrm() const{
                return _flags & 0b1000;
            }
            std::byte default_op_r() const{
                return default_opr;
            }
            void encode_mandatory_prefix(bytes& buf) const{
                if(_flags&0b100){
                    buf.append(prefix);
                }
            }
            void encode_opcode(bytes& buf,width opw) const{
                width native_width{unpack_width(static_cast<std::byte>(_flags)>>6)};
                if((native_width==width::W8) != (opw==width::W8)){
                    throw std::logic_error("encode_opcode: Trying to encode a wide operand with a 8-bit instruction, or vice versa");
                }else if(opw==width::W64){
                    buf.append(0b01001000_b); // REX.W
                }else if(native_width==width::W64&&opw==width::W32){ // e.g. dword PUSH/POP on 64-bit
                    throw std::logic_error("encode_opcode: Operation does not support 32-bit operands");
                }else if(opw!=native_width){
                    buf.append(0x66_b);
                }
                buf.append(std::span<const std::byte>(_opcode,_flags&3));
            }
    };
    class Instruction{
        // 00dd rspp
        // d: size of displacement
        // s: presence of SIB byte
        // r: presence of REX prefix // TODO
        // p: number of prefixes
        const InstructionEncoding* ienc;
        std::uint8_t _flags{0};
        std::byte _lpref[4];
        width opwidth;
        std::byte _modrm{0_b};
        std::byte _sib;
        std::byte _disp[4];
        std::byte _imm[4];
        template<bool ret_disp>
        std::conditional_t<ret_disp,std::uint64_t,void> _encode(bytes& buf) const{
            buf.append(std::span<const std::byte>(_lpref,_flags&0b11));
            ienc->encode_mandatory_prefix(buf);
            ienc->encode_opcode(buf,opwidth);
            if(ienc->has_modrm()){
                buf.append(_modrm);
            }
            if(_flags&0b100){
                buf.append(_sib);
            }
            std::uint64_t dbegin = buf.size();
            buf.append(std::span<const std::byte>(_disp,1uz<<(_flags>>4uz)>>1uz));
            if(ienc->has_immediate()){
                buf.append(std::span<const std::byte>(_imm,width_to_byte_count(
                    opwidth==width::W64?width::W32:opwidth
                )));
            }
            if constexpr(ret_disp){
                return dbegin;
            }
        }
        public:
            Instruction() : ienc(nullptr){}
            Instruction(const InstructionEncoding& enc) : ienc(&enc){
                rm_reg(enc.default_op_r());
            }
            void reset(const InstructionEncoding& enc){
                ienc = &enc;
                rm_reg(enc.default_op_r());
            }
            const InstructionEncoding& encoding() const{
                return *ienc;
            }
            void reset(){
                _flags = 0;
                std::ranges::fill(_lpref,0_b);
            }
            void sib(std::byte b){
                _sib = b;
            }
            void sib(std::byte base,std::byte index,std::byte scale){
                _sib = (scale << 6) | (index << 3) | base;
            }
            void prefix(std::byte pref){
                _lpref[_flags&0b11] = pref;
                ++_flags; // can't carry into the third bit unless there are 5 prefixes, which can't happen
            }
            void set_width(width wd){
                opwidth = wd;
            }
            void mod_rm(std::byte mod,std::byte rm){
                _modrm |= (mod << 6) | rm;
            }
            void rm_reg(std::byte reg){
                _modrm |= reg << 3;
            }
            void displacement(std::uint8_t u8){
                _flags |= (1 << 4);
                _disp[0] = static_cast<std::byte>(u8);
            }
            void displacement(std::uint16_t u16){
                _flags |= (2 << 4);
                _disp[0] = static_cast<std::byte>(u16);
                _disp[1] = static_cast<std::byte>(u16>>8);
            }
            void displacement(std::uint32_t u32){
                _flags |= (3 << 4);
                _disp[0] = static_cast<std::byte>(u32);
                _disp[1] = static_cast<std::byte>(u32>>8);
                _disp[2] = static_cast<std::byte>(u32>>16);
                _disp[3] = static_cast<std::byte>(u32>>24);
            }
            void immediate(std::uint8_t u8){
                _imm[0] = static_cast<std::byte>(u8);
            }
            void immediate(std::uint16_t u16){
                _imm[0] = static_cast<std::byte>(u16);
                _imm[1] = static_cast<std::byte>(u16>>8);
            }
            void immediate(std::uint32_t u32){
                _imm[0] = static_cast<std::byte>(u32);
                _imm[1] = static_cast<std::byte>(u32>>8);
                _imm[2] = static_cast<std::byte>(u32>>16);
                _imm[3] = static_cast<std::byte>(u32>>24);
            }
            void encode(bytes& buf) const{
                _encode<false>(buf);
            }
            std::uint64_t encode_and_return_disp(bytes& buf) const{
                return _encode<true>(buf);
            }
    };
    namespace encode{
        namespace detail{
            template<std::byte base>
            struct ins{
                constexpr static InstructionEncoding rm_r{
                    width::W32,
                    std::nullopt,
                    {static_cast<std::byte>(static_cast<std::uint8_t>(base)+1)},
                    true,
                    true,
                    true,
                    0_b,
                    false
                };
                constexpr static InstructionEncoding rm_r_8{
                    width::W8,
                    std::nullopt,
                    {base},
                    true,
                    true,
                    true,
                    0_b,
                    false
                };
                constexpr static InstructionEncoding r_rm{
                    width::W32,
                    std::nullopt,
                    {static_cast<std::byte>(static_cast<std::uint8_t>(base)+3)},
                    true,
                    false,
                    true,
                    0_b,
                    false
                };
                constexpr static InstructionEncoding r_rm_8{
                    width::W8,
                    std::nullopt,
                    {static_cast<std::byte>(static_cast<std::uint8_t>(base)+2)},
                    true,
                    false,
                    true,
                    0_b,
                    false
                };
            };
            template<std::byte base,std::byte opr>
            struct ins_imm{
                constexpr static InstructionEncoding rm_imm{
                    width::W32,
                    std::nullopt,
                    {static_cast<std::byte>(static_cast<std::uint8_t>(base)+1)},
                    true,
                    true,
                    true,
                    opr,
                    true
                };
                constexpr static InstructionEncoding rm_imm_8{
                    width::W8,
                    std::nullopt,
                    {base},
                    true,
                    true,
                    true,
                    opr,
                    true
                };
            };
        }
        struct add : detail::ins<0x00_b>, detail::ins_imm<0x80_b,0_b>{};
        struct sub : detail::ins<0x28_b>, detail::ins_imm<0x80_b,5_b>{};
        struct mov : detail::ins<0x88_b>, detail::ins_imm<0xC6_b,0_b>{};
        constexpr inline InstructionEncoding lea{
            width::W32,
            std::nullopt,
            {0x8D_b},
            true,
            false,
            true,
            0_b,
            false
        };
        namespace detail{
            template<std::byte rmop,std::byte rmreg,std::byte rop>
            struct pushpop{
                constexpr static InstructionEncoding rm{
                    width::W64,
                    std::nullopt,
                    {rmop},
                    true,
                    true,
                    true,
                    rmreg,
                    false
                };
                constexpr static void r64(bytes& buf,std::byte r){
                    buf.append(static_cast<std::byte>(static_cast<std::uint8_t>(rop)+static_cast<std::uint8_t>(r)));
                }
                constexpr static void r16(bytes& buf,std::byte r){
                    buf.append(0x66_b);
                    buf.append(static_cast<std::byte>(static_cast<std::uint8_t>(rop)+static_cast<std::uint8_t>(r)));
                }
            };
        }
        struct push : detail::pushpop<0xFF_b,6_b,0x50_b>{};
        struct pop : detail::pushpop<0x8F_b,0_b,0x58_b>{};
        struct call{
            constexpr static InstructionEncoding rm{
                width::W64,
                std::nullopt,
                {0xFF_b},
                true,
                true,
                false,
                0x2_b,
                false
            };
            constexpr static void rel32(bytes& buf,std::uint32_t rel){
                buf.append(0xE8_b);
                buf.append(rel);
            }
        };
        struct ret{
            constexpr static void near(bytes& buf){
                buf.append(0xC3_b);
            }
            constexpr static void far(bytes& buf){
                buf.append(0xCB_b);
            }
        };
        constexpr inline void leave(bytes& buf){
            buf.append(0xC9_b);
        }
    }
}
