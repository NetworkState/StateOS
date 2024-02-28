
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.


#include "Types.h"

constexpr UINT32 STR_UINT32(const char* chars)
{
    auto length = stringLen(chars);
    UINT32 value = 0;
    for (UINT32 i = 0; i < length; i++)
    {
        value = (value << 8) | chars[i];
    }
    return value;
}

constexpr UINT32 OP_INDEX_START = __COUNTER__;
#define OPINDX_ (__COUNTER__ - OP_INDEX_START)

struct JS_OPERATOR
{
    TOKEN op;
    UINT32 chars;
    constexpr JS_OPERATOR(const char* string, UINT32 index, UINT32 precedence)
    {
        chars = STR_UINT32(string);
        ASSERT(chars != 0);
        op = TOKEN(TOKEN_SYMBOL, TF_JS_OPERATOR, precedence << 8 | index);
    }

    constexpr JS_OPERATOR(TOKEN name, UINT32 index, UINT32 precedence)
    {
        chars = name.toUInt32();
        ASSERT(chars != 0);
        op = TOKEN(TOKEN_SYMBOL, TF_JS_OPERATOR, precedence << 8 | index);
    }

    constexpr JS_OPERATOR() : op(Null), chars(0) {}

    UINT8 getPrecedence()
    {
        return UINT8(op.getValue() >> 8);
    }

    constexpr bool operator == (const JS_OPERATOR other) const { return this->op == other.op; }

    explicit operator bool() const { return chars != 0; }
};

constexpr auto OP_INVALID = JS_OPERATOR();
constexpr auto OP_INCREMENT = JS_OPERATOR("++", OPINDX_, 14);
constexpr auto OP_DECREMENT = JS_OPERATOR("--", OPINDX_, 14);
constexpr auto OP_LPAREN = JS_OPERATOR("(", OPINDX_, 18);
constexpr auto OP_RPAREN = JS_OPERATOR(")", OPINDX_, 18);
constexpr auto OP_LBRACKET = JS_OPERATOR("[", OPINDX_, 17);
constexpr auto OP_RBRACKET = JS_OPERATOR("]", OPINDX_, 17);
constexpr auto OP_DOT = JS_OPERATOR(".", OPINDX_, 17);
constexpr auto OP_SPREAD = JS_OPERATOR("...", OPINDX_, 2);
constexpr auto OP_SEMICOLON = JS_OPERATOR(";", OPINDX_, 1);
constexpr auto OP_COMMA = JS_OPERATOR(",", OPINDX_, 1);
constexpr auto OP_LT = JS_OPERATOR("<", OPINDX_, 9);
constexpr auto OP_GT = JS_OPERATOR(">", OPINDX_, 9);
constexpr auto OP_LTE = JS_OPERATOR("<=", OPINDX_, 9);
constexpr auto OP_GTE = JS_OPERATOR(">=", OPINDX_, 9);
constexpr auto OP_EQ = JS_OPERATOR("==", OPINDX_, 8);
constexpr auto OP_NEQ = JS_OPERATOR("!=", OPINDX_, 8);
constexpr auto OP_STRICT_EQ = JS_OPERATOR("===", OPINDX_, 8);
constexpr auto OP_STRICT_NEQ = JS_OPERATOR("!==", OPINDX_, 8);
constexpr auto OP_CHAIN_DOT = JS_OPERATOR("?.", OPINDX_, 17);

constexpr auto OP_MINUS = JS_OPERATOR("-", OPINDX_, 11);
constexpr auto OP_PLUS = JS_OPERATOR("+", OPINDX_, 11);
constexpr auto OP_MULTIPLY = JS_OPERATOR("*", OPINDX_, 12);
constexpr auto OP_DIVIDE = JS_OPERATOR("/", OPINDX_, 12);
constexpr auto OP_EXP = JS_OPERATOR("**", OPINDX_, 13);
constexpr auto OP_MOD = JS_OPERATOR("%", OPINDX_, 12);
constexpr auto OP_SHL = JS_OPERATOR("<<", OPINDX_, 10);
constexpr auto OP_SHR = JS_OPERATOR(">>", OPINDX_, 10);
constexpr auto OP_UNSIGNED_SHR = JS_OPERATOR(">>>", OPINDX_, 10);
constexpr auto OP_BIT_AND = JS_OPERATOR("&", OPINDX_, 7);

constexpr auto OP_BIT_OR = JS_OPERATOR("|", OPINDX_, 5);
constexpr auto OP_BIT_XOR = JS_OPERATOR("^", OPINDX_, 6);
constexpr auto OP_NOT = JS_OPERATOR("!", OPINDX_, 14);
constexpr auto OP_BIT_NOT = JS_OPERATOR("~", OPINDX_, 14);
constexpr auto OP_LOGICAL_AND = JS_OPERATOR("&&", OPINDX_, 4);
constexpr auto OP_LOGICAL_OR = JS_OPERATOR("||", OPINDX_, 3);
constexpr auto OP_ON_NULL = JS_OPERATOR("??", OPINDX_, 3);
constexpr auto OP_TERNARY1 = JS_OPERATOR("?", OPINDX_, 2);
constexpr auto OP_TERNARY2 = JS_OPERATOR(":", OPINDX_, 2);
constexpr auto OP_ASSIGN = JS_OPERATOR("=", OPINDX_, 2);

constexpr auto OP_ADD_ASSIGN = JS_OPERATOR("+=", OPINDX_, 2);
constexpr auto OP_SUB_ASSIGN = JS_OPERATOR("-=", OPINDX_, 2);
constexpr auto OP_MULT_ASSIGN = JS_OPERATOR("*=", OPINDX_, 2);
constexpr auto OP_DIV_ASSIGN = JS_OPERATOR("/=", OPINDX_, 2);
constexpr auto OP_MOD_ASSIGN = JS_OPERATOR("%=", OPINDX_, 2);
constexpr auto OP_BIT_OR_ASSIGN = JS_OPERATOR("|=", OPINDX_, 2);
constexpr auto OP_BIT_AND_ASSIGN = JS_OPERATOR("&=", OPINDX_, 2);
constexpr auto OP_BIT_XOR_ASSIGN = JS_OPERATOR("^=", OPINDX_, 2);
constexpr auto OP_LOGICAL_OR_ASSIGN = JS_OPERATOR("||=", OPINDX_, 2);
constexpr auto OP_LOGICAL_AND_ASSIGN = JS_OPERATOR("&&=", OPINDX_, 2);

constexpr auto OP_ON_NULL_ASSIGN = JS_OPERATOR("??=", OPINDX_, 2);
constexpr auto OP_EXP_ASSIGN = JS_OPERATOR("**=", OPINDX_, 2);
constexpr auto OP_SHL_ASSIGN = JS_OPERATOR("<<=", OPINDX_, 2);
constexpr auto OP_SHR_ASSIGN = JS_OPERATOR(">>=", OPINDX_, 2);
constexpr auto OP_UNSIGNED_SHR_ASSIGN = JS_OPERATOR(">>>=", OPINDX_, 2);
constexpr auto OP_ARROW = JS_OPERATOR("=>", OPINDX_, 2);

constexpr auto OP_YIELD = JS_OPERATOR(JS_yield, OPINDX_, 2);
constexpr auto OP_IN = JS_OPERATOR(JS_in, OPINDX_, 9);
constexpr auto OP_INSTANCE_OF = JS_OPERATOR(JS_instanceof, OPINDX_, 9);
constexpr auto OP_TYPEOF = JS_OPERATOR(JS_typeof, OPINDX_, 14);
constexpr auto OP_VOID = JS_OPERATOR(JS_void, OPINDX_, 14);
constexpr auto OP_DELETE = JS_OPERATOR(JS_delete, OPINDX_, 14);
constexpr auto OP_AWAIT = JS_OPERATOR(JS_await, OPINDX_, 14);
constexpr auto OP_NEW = JS_OPERATOR(JS_new, OPINDX_, 17);

constexpr JS_OPERATOR JSOperators[64] = {
    OP_INCREMENT, OP_DECREMENT, OP_LPAREN, OP_RPAREN, OP_LBRACKET, OP_RBRACKET, OP_DOT, OP_SPREAD, OP_SEMICOLON, OP_COMMA,
    OP_LT, OP_GT, OP_LTE, OP_GTE, OP_EQ, OP_NEQ, OP_STRICT_EQ, OP_STRICT_NEQ, OP_CHAIN_DOT,
    OP_MINUS, OP_PLUS, OP_MULTIPLY, OP_DIVIDE, OP_EXP, OP_MOD, OP_SHL, OP_SHR, OP_UNSIGNED_SHR, OP_BIT_AND,
    OP_BIT_OR, OP_BIT_XOR, OP_NOT, OP_BIT_NOT, OP_LOGICAL_AND, OP_LOGICAL_OR, OP_ON_NULL, OP_TERNARY1, OP_TERNARY2, OP_ASSIGN,
    OP_ADD_ASSIGN, OP_SUB_ASSIGN, OP_MULT_ASSIGN, OP_DIV_ASSIGN, OP_MOD_ASSIGN,
    OP_BIT_OR_ASSIGN, OP_BIT_AND_ASSIGN, OP_BIT_XOR_ASSIGN, OP_LOGICAL_OR_ASSIGN, OP_LOGICAL_AND_ASSIGN, OP_ON_NULL_ASSIGN,
    OP_EXP_ASSIGN, OP_SHL_ASSIGN, OP_SHR_ASSIGN, OP_UNSIGNED_SHR_ASSIGN, OP_ARROW, OP_YIELD, OP_IN, OP_INSTANCE_OF, OP_TYPEOF,
    OP_VOID, OP_DELETE, OP_AWAIT, OP_NEW,
};

constexpr TOKEN JSKeywords[64] = {
    JS_await, JS_break, JS_case, JS_catch, JS_class, JS_const, JS_continue, JS_debugger, JS_default, JS_delete, JS_do, JS_else, JS_enum,
    JS_export, JS_extends, JS_false, JS_finally, JS_for, JS_function, JS_if, JS_import, JS_in, JS_instanceof, JS_new, JS_null, JS_return,
    JS_super, JS_switch, JS_this, JS_throw, JS_true, JS_try, JS_typeof, JS_var, JS_void, JS_while, JS_with, JS_yield
};

constexpr static UINT8 CC_JS_WHITESPACE = 0x10;
constexpr static UINT8 CC_JS_NAME = 0x01;
constexpr static UINT8 CC_JS_SEPARATOR = 0x02;
constexpr static UINT8 CC_JS_OPERATOR = 0x04;
constexpr static UINT8 CC_JS_QUOTE = 0x08;
constexpr static UINT8 CC_JS_END_QUOTE = 0x20;
constexpr static UINT8 CC_JS_NON_QUOTE = 0x40;
constexpr static UINT8 CC_JS_UNKNOWN = 0x80;

constexpr static UINT8 JS_CS_NAME[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_";
constexpr static UINT8 JS_CS_OPERATOR[] = "<>=!+-%/*&^~?|";
constexpr static UINT8 JS_CS_SEPARATOR[] = "\\{}[]().,;:'";
constexpr static UINT8 JS_CS_QUOTE[] = "\"'`";
constexpr static UINT8 JS_CS_WHITESPACE[] = "\r\n\t ";

struct CC_JS_MAP
{
    UINT8 data[128] = { 0 };
    constexpr CC_JS_MAP()
    {
        for (UINT8 i = 0; i < 128; i++)
        {
            data[i] = CC_JS_UNKNOWN;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JS_CS_NAME); i++)
        {
            data[JS_CS_NAME[i]] = CC_JS_NAME;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JS_CS_OPERATOR); i++)
        {
            data[JS_CS_OPERATOR[i]] = CC_JS_OPERATOR;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JS_CS_SEPARATOR); i++)
        {
            data[JS_CS_SEPARATOR[i]] = CC_JS_SEPARATOR;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JS_CS_QUOTE); i++)
        {
            data[JS_CS_QUOTE[i]] = CC_JS_QUOTE;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JS_CS_WHITESPACE); i++)
        {
            data[JS_CS_WHITESPACE[i]] = CC_JS_WHITESPACE;
        }
    }
};
constexpr static CC_JS_MAP JS_MAP;

struct CC_JS_QUOTE_MAP
{
    UINT8 data[128] = { 0 };
    UINT8 quoteChar;
    constexpr CC_JS_QUOTE_MAP(UINT8 quoteChar) : quoteChar(quoteChar)
    {
        for (UINT8 i = 0; i < 128; i++)
        {
            data[i] = CC_JS_NON_QUOTE;
        }
        data[quoteChar] = CC_JS_END_QUOTE;
        data['\\'] = CC_JS_END_QUOTE;
    }
};
constexpr static CC_JS_QUOTE_MAP JS_DQUOTE_MAP{ '"' }; // double quote
constexpr static CC_JS_QUOTE_MAP JS_SQUOTE_MAP{ '\'' }; // single quote
constexpr static CC_JS_QUOTE_MAP JS_BQUOTE_MAP{ '`' }; // back tick - reverse quote - back quote

struct CC_JS_ESCAPE_SEQ
{
    UINT8 data[128] = { 0 };
    constexpr CC_JS_ESCAPE_SEQ()
    {
        for (UINT8 i = 0; i < 128; i++)
        {
            data[i] = i;
        }
        data['n'] = '\n';
        data['r'] = '\r';
        data['t'] = '\t';
        data['b'] = '\b';
        data['f'] = '\f';
    }
};
constexpr static CC_JS_ESCAPE_SEQ CC_JS_ESCAPE;

/*`
( ) [ ] . ... ; , < > <= >= == != === !== + - * % ** ++ -- << >> >>> & | ^ !
~ && || ?? ? : = += -= *= %= **= <<= >>= >>>= &= |= ^= &&= ||= ??= =>
*/
template <UINT32 SZ = 1>
struct PARSE_JSON
{
    BUFFER jsonText;
    __m512i symbolClassMap1, symbolClassMap2;
    BYTESTREAM symbolStream;
    BYTESTREAM quoteStream;

    PARSE_JSON(BUFFER jsonText) : jsonText(jsonText)
    {
        symbolClassMap1 = _mm512_loadu_epi8(JSON_MAP.data);
        symbolClassMap2 = _mm512_loadu_epi8(JSON_MAP.data + 64);

        symbolStream.allocReserve<SCHEDULER_STACK>(jsonText.length() * 2); // = ByteStream(jsonText.length() * 2);
        quoteStream.allocReserve<SCHEDULER_STACK>(jsonText.length()); //= ByteStream(jsonText.length());
    }

    BUFFER splitSymbol(const __m512i& map1, const __m512i& map2, UINT8& symbolClass)
    {
        __m512i textReg;
        auto bytesRead = loadRegister(jsonText, textReg);
        auto textMask = MASK(bytesRead);
        auto classReg = _mm512_maskz_permutex2var_epi8(textMask, map1, textReg, map2);

        // spread the first byte across
        auto reg = _mm512_maskz_permutexvar_epi8(textMask, _mm512_set1_epi8(0), classReg);
        auto transitionMask = _mm512_mask_testn_epi8_mask(textMask, classReg, reg);

        auto count = min(bytesRead, (UINT32)_tzcnt_u64(transitionMask));
        jsonText.shift(count);

        auto symbolStart = symbolStream.count();
        _mm512_mask_storeu_epi8(symbolStream.commit(count), MASK(count), textReg);
        auto symbol = symbolStream.toBuffer(symbolStart);

        _mm512_mask_storeu_epi8(&symbolClass, 1, classReg);

        return symbol;
    }

    BUFFER splitQuote(UINT8 quoteChar)
    {
        auto&& quoteMap = quoteChar == '"' ? JS_DQUOTE_MAP : JS_SQUOTE_MAP;

        auto quoteClassMap1 = _mm512_loadu_epi8(quoteMap.data);
        auto quoteClassMap2 = _mm512_loadu_epi8(quoteMap.data + 64);

        quoteStream.clear();
        while (jsonText)
        {
            UINT8 symbolClass;
            auto symbol = splitSymbol(quoteClassMap1, quoteClassMap2, symbolClass);
            if (symbolClass == CC_JSON_END_QUOTE)
            {
                auto escapeChar = symbol.readByte();
                do
                {
                    if (escapeChar == '\\')
                    {
                        auto nextChar = symbol ? symbol.readByte() : jsonText.readByte();
                        if (nextChar != 'u')
                        {
                            quoteStream.writeByte(CC_JSON_ESCAPE.data[nextChar]);
                        }
                        else DBGBREAK();
                    }
                    else if (escapeChar == '"')
                    {
                        break;
                    }
                } while (symbol);
                if (escapeChar == '"')
                    break;
            }
            else
            {
                quoteStream.writeBytes(symbol);
            }
        }
        return quoteStream.toBuffer();
    }

    template <typename FUNC, typename ... ARGS>
    void parseJson(FUNC&& func, ARGS&& ... args)
    {
        UINT8 lastSeparator = 0;
        TOKEN lastName;
        while (jsonText)
        {
            UINT8 symbolClass;
            auto symbol = splitSymbol(symbolClassMap1, symbolClassMap2, symbolClass);
            if (symbolClass == CC_JSON_QUOTE)
            {
                jsonText.shift(1 - symbol.length()); // put back remaining quote chars (empty quote)
                symbol = splitQuote(symbol.readByte());
            }
            ASSERT(symbol);
            if (symbolClass == CC_JSON_NAME || symbolClass == CC_JSON_QUOTE)
            {
                if (lastSeparator == ':')
                {
                    func(lastName, symbol, args ...);
                }
                else
                {
                    lastName = Dict.CreateName<SERVICE_STACK>(symbol);
                }
            }
            else if (symbolClass == CC_JSON_SEPARATOR)
            {
                lastSeparator = symbol.readByte();
            }
        }
    }
};

using U32_INDEX_MAP = UINT32[64];
U32_INDEX_MAP JSOperatorMap = { 0 };
U32_INDEX_MAP JSKeywordMap = { 0 };

void InitJson()
{
    for (UINT32 i = 0; i < ARRAYSIZE(JSOperators); i++)
    {
        JSOperatorMap[i] = JSOperators[i].chars;
    }
    for (UINT32 i = 0; i < ARRAYSIZE(JSKeywords); i++)
    {
        JSKeywordMap[i] = JSKeywords[i].toUInt32();
    }
}

UINT64 matchName(UINT32 value, U32_INDEX_MAP& names)
{
    auto matchReg = _mm512_set1_epi32(value);

    auto opReg1 = _mm512_loadu_epi32(names);
    auto opReg2 = _mm512_loadu_epi32(names + 16);
    auto opReg3 = _mm512_loadu_epi32(names + 32);
    auto opReg4 = _mm512_loadu_epi32(names + 48);

    UINT64 matchMask1 = _mm512_cmpeq_epi32_mask(opReg1, matchReg);
    UINT64 matchMask2 = _mm512_cmpeq_epi32_mask(opReg2, matchReg);
    UINT64 matchMask3 = _mm512_cmpeq_epi32_mask(opReg3, matchReg);
    UINT64 matchMask4 = _mm512_cmpeq_epi32_mask(opReg4, matchReg);

    UINT64 matchMask = matchMask1 | (matchMask2 << 16) | (matchMask3 << 32) | (matchMask4 << 48);
    return matchMask;
}

JS_OPERATOR IsOperator(UINT32 name)
{
    auto matchMask = matchName(name, JSOperatorMap);
    ASSERT(POPCNT(matchMask) == 0 || (POPCNT(matchMask) == 1));
    return matchMask ? JSOperators[_tzcnt_u64(matchMask)] : OP_INVALID;
}

TOKEN IsKeyword(TOKEN symbol)
{
    auto matchMask = matchName(symbol.toUInt32(), JSKeywordMap);
    ASSERT(POPCNT(matchMask) == 0 || (POPCNT(matchMask) == 1));
    return matchMask ? JSKeywords[_tzcnt_u64(matchMask)] : Null;
}

void parseArticle(BUFFER text)
{

}

TOKEN textField;
void ParseNews()
{
    textField = Dict.CreateName<SERVICE_STACK>("text");
    auto jsonText = File.ReadFile<SERVICE_STACK>("test\\test1.json");
    PARSE_JSON jsonParser{ jsonText };
    jsonParser.parseJson([](TOKEN name, BUFFER value)
        {
            if (name == textField)
            {
                parseArticle(value);
            }
        });
}

void TestJson()
{
    ParseNews();
}
