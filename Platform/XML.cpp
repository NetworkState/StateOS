
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#include "Types.h"

enum class CC_XML : UINT8
{
	CC_XML_UNKNOWN = 0,
	CC_XML_ENTITY = 0x01,
	CC_XML_SEPARATOR = 0x02,
	CC_XML_TAG = 0x04,
	CC_XML_NAME = 0x08,
	CC_XML_DOUBLEQUOTE = 0x10,
	CC_XML_SINGLEQUOTE = 0x20,
	CC_XML_WHITESPACE = 0x40,
};
DEFINE_ENUM_FLAG_OPERATORS(CC_XML);
using enum CC_XML;

constexpr static UINT8 XML_CS_TAG[] = "</>";
constexpr static UINT8 XML_CS_SEPARATOR[] = "=";
constexpr static UINT8 XML_CS_ENTITY[] = "&";
constexpr static UINT8 XML_CS_QUOTE[] = "\"'";
constexpr static UINT8 XML_CS_WHITESPACE[] = "\r\n\t ";

constexpr static auto CC_DOUBLEQUOTE_FILTER = CC_XML_DOUBLEQUOTE | CC_XML_ENTITY;
constexpr static auto CC_SINGLEQUOTE_FILTER = CC_XML_SINGLEQUOTE | CC_XML_ENTITY;
constexpr static CC_XML CC_DEFAULT_FILTER = CC_XML(0xFF);
constexpr bool IGNORE_WHITESPACE = true;

using PERMUTEMAP2 = UINT8[128];
using PERMUTEMAP1 = UINT8[64];

struct CC_XML_MAP
{
	PERMUTEMAP2 data{ 0 };
	constexpr CC_XML_MAP()
	{
		for (UINT32 i = 0; i < 0x20; i++)
		{
			data[i] = (UINT8)CC_XML_UNKNOWN;
		}

		for (UINT32 i = 0x20; i <= 0x7F; i++)
		{
			data[i] = (UINT8)CC_XML_NAME;
		}

		for (UINT32 i = 0; i < ARRAYSIZE(XML_CS_TAG); i++)
		{
			data[XML_CS_TAG[i]] = (UINT8)CC_XML_TAG;
		}

		for (UINT32 i = 0; i < ARRAYSIZE(XML_CS_ENTITY); i++)
		{
			data[XML_CS_ENTITY[i]] = (UINT8)CC_XML_ENTITY;
		}

		for (UINT32 i = 0; i < ARRAYSIZE(XML_CS_SEPARATOR); i++)
		{
			data[XML_CS_SEPARATOR[i]] = (UINT8)CC_XML_SEPARATOR;
		}

		for (UINT32 i = 0; i < ARRAYSIZE(XML_CS_WHITESPACE); i++)
		{
			data[XML_CS_WHITESPACE[i]] = (UINT8)CC_XML_WHITESPACE;
		}

		data['"'] = (UINT8)CC_XML_DOUBLEQUOTE;
		data['\''] = (UINT8)CC_XML_SINGLEQUOTE;
	}
};
constexpr static CC_XML_MAP XML_MAP;

struct PARSE_XML
{
	BUFFER xmlText;
	BYTESTREAM symbolStream, quoteStream, textStream;
	DATASTREAM<VLTOKEN, SERVICE_STACK> tokenStream;

	UINT32 attrNameDict = 5, attrValueDict = 6;
	UINT32 elementNameDict = 0;

	UINT32 vlTokenIdent = 0;
	UINT32 currentIndent = 0;

	PARSE_XML(BUFFER xmlText) : xmlText(xmlText)
	{
		auto byteLength = xmlText.length();

		symbolStream.tempAlloc(byteLength); // = ByteStream(byteLength);
		quoteStream.tempAlloc(byteLength); // = ByteStream(byteLength);
		textStream.tempAlloc(byteLength); // = ByteStream(byteLength);

		tokenStream.reserve(byteLength / 8);
	}

	inline bool splitDirective()
	{
		auto result = false;
		if ((xmlText.length() > 2) && (xmlText.at(0) == '<') && (xmlText.at(1) == '!'))
		{
			xmlText.shift(2);
			BUFFER terminator = ((xmlText.at(0) == '-') && (xmlText.at(1) == '-')) ? "-->" : ">";
			String.splitStringIf(xmlText, terminator);
			result = true;
		}
		return result;
	}

	BUFFER splitSymbol(CC_XML& symbolClass, CC_XML filter, bool ignoreWhitespace)
	{
		symbolClass = CC_XML_UNKNOWN;

		auto streamOffset = symbolStream.getPosition();
		__m512i classMap1 = _mm512_loadu_epi8(XML_MAP.data);
		__m512i classMap2 = _mm512_loadu_epi8(XML_MAP.data + 64);

		while (xmlText)
		{
			splitDirective();

			__m512i textReg;
			auto bytesRead = loadRegister(xmlText, textReg);
			auto textMask = MASK(bytesRead);

			auto classReg = _mm512_maskz_permutex2var_epi8(textMask, classMap1, textReg, classMap2);

			// spread the first byte across
			auto reg = _mm512_maskz_permutexvar_epi8(textMask, _mm512_set1_epi8(0), classReg);
			auto transitionMask = _mm512_mask_testn_epi8_mask(textMask, classReg, reg);

			auto count = min(bytesRead, (UINT32)_tzcnt_u64(transitionMask));
			xmlText.shift(count);
			_mm512_mask_storeu_epi8(&symbolClass, 1, classReg);

			if (symbolClass == CC_XML_WHITESPACE && ignoreWhitespace)
				continue;

			_mm512_mask_storeu_epi8(symbolStream.commit(count), MASK(count), textReg);

			if (splitDirective())
				continue;

			if ((symbolClass & filter) != CC_XML_UNKNOWN)
				break;
		}
		return streamOffset.toBuffer();
	}

	UINT8 splitEntity()
	{
		auto entityText = String.splitCharIf(xmlText, ';', 8);
		UINT8 entityChar = (entityText == "lt") ? '<' :
			(entityText == "gt") ? '>' :
			(entityText == "apos") ? '\'' :
			(entityText == "amp") ? '&' :
			(entityText == "quot") ? '"' : 0;

		if (entityText) ASSERT(entityChar);
		return entityChar;
	}

	BUFFER splitQuote(UINT8 quoteChar)
	{
		quoteStream.clear();
		auto quoteClass = quoteChar == '"' ? CC_XML_DOUBLEQUOTE : CC_XML_SINGLEQUOTE;
		auto filter = quoteClass | CC_XML_ENTITY;

		CC_XML symbolClass;
		while (auto nextSymbol = splitSymbol(symbolClass, filter, false))
		{
			if (symbolClass == CC_XML_ENTITY)
			{
				auto entityChar = splitEntity();
				quoteStream.writeByte(entityChar ? entityChar : '&');
			}
			else if (symbolClass == quoteClass)
			{
				quoteStream.writeBytes(nextSymbol, nextSymbol.length() - 1);
				break;
			}
		}
		return quoteStream.toBuffer();
	}

	BUFFER splitContent(BUFFER tagName)
	{
		BUFFER content;
		auto contentStart = xmlText;
		auto closingTag = ByteStream(256).writeMany("</", tagName, ">");

		CC_XML symbolClass;
		BUFFER nextSymbol;
		while (nextSymbol = splitSymbol(symbolClass, CC_DEFAULT_FILTER, true))
		{
			if (symbolClass == CC_XML_TAG)
			{
				if (nextSymbol == "</")
				{
					auto terminator = String.splitCharIf(xmlText, '>');
					ASSERT(terminator);
					break;
				}
				else if (nextSymbol == "<")
				{
					splitNode();
				}
				else DBGBREAK();
			}
			else break;
		}

		if (symbolClass != CC_XML_TAG)
		{
			content = String.splitStringIf(xmlText, closingTag);
		}
		return content;
	}

	struct ATTR_TRACK
	{
		PARSE_XML& parser;
		UINT32 indent;
		BUFFER nameText;
		BUFFER valueText;
		bool valueExpected = false;

		ATTR_TRACK(PARSE_XML& parser, UINT32 indent) : parser(parser), indent(indent) {}
		void upcall()
		{
			auto valueToken = ServiceTokens.createLabel(parser.attrValueDict, valueText);
			auto nameToken = ServiceTokens.createLabel(parser.attrNameDict, nameText);

			parser.insertVLtoken(valueToken, nameToken, indent);
			nameText = valueText = NULL_BUFFER;
			valueExpected = false;
		}

		void addText(BUFFER text)
		{
			if (valueExpected)
			{
				ASSERT(nameText);
				valueText = text;
				upcall();
			}
			else
			{
				if (nameText)
				{
					upcall();
				}
				nameText = text;
			}
		}

		void addSeparator(UINT8 separator)
		{
			valueExpected = true;
		}
	};

	constexpr VL_SEPARATION getSeparation(UINT32 indent) { return VL_SEPARATION(UINT8(VS_BLOCK) + indent - vlTokenIdent); }

	VLTOKEN& insertVLtoken(TOKEN contour, TOKEN label, UINT32 indent)
	{
		auto&& newToken = tokenStream.append(contour, label, getSeparation(indent));
		vlTokenIdent = indent;
		return newToken;
	}

	void splitNode()
	{
		++currentIndent;
		ATTR_TRACK attrTracker (*this, currentIndent + 1);

		CC_XML symbolClass;
		auto tagName = splitSymbol(symbolClass, CC_DEFAULT_FILTER, true);
		ASSERT(symbolClass == CC_XML_NAME);

		auto nameToken = FindName(tagName);
		ASSERT(nameToken);

		auto&& nodeToken = insertVLtoken(NULL_NAME, nameToken, currentIndent);

		BUFFER attrName, attrValue, attrFlag;
		while (auto nextSymbol = splitSymbol(symbolClass, CC_DEFAULT_FILTER, true))
		{
			if (symbolClass == CC_XML_SEPARATOR)
			{
				auto separator = nextSymbol.peek();
				if (separator == '=')
				{
					attrTracker.addSeparator(separator);
				}
				else DBGBREAK();
			}
			else if (symbolClass == CC_XML_TAG)
			{
				auto firstChar = nextSymbol.readByte();
				if ((firstChar == '/') && nextSymbol && (nextSymbol.readByte() == '>'))
				{
					xmlText.shift(0 - nextSymbol.length());
					break;
				}
				else if (firstChar == '>') // corner case, "></"
				{
					xmlText.shift(0 - nextSymbol.length());
					splitContent(tagName);
					break;
				}
				else DBGBREAK();
			}
			else if (symbolClass == CC_XML_NAME)
			{
				attrTracker.addText(nextSymbol);
			}
			else if ((symbolClass & (CC_XML_DOUBLEQUOTE | CC_XML_SINGLEQUOTE)) != CC_XML_UNKNOWN)
			{
				auto quoteChar = nextSymbol.readByte();
				BUFFER text;
				if ((nextSymbol.length() == 0) || (nextSymbol.peek() != quoteChar))
				{
					text = splitQuote(quoteChar);
				}
				attrTracker.addText(text);
			}
			else DBGBREAK();
		}
		currentIndent--;
	}

	void parseXml()
	{
		CC_XML symbolClass;
		auto nextSymbol = splitSymbol(symbolClass, CC_XML_TAG, true);
		if (symbolClass == CC_XML_TAG)
		{
			splitNode();
		}
		else DBGBREAK();
	}
};

void TestXmlParser()
{
	auto xmlText = File.ReadFile<SERVICE_STACK>("test\\test.xml");
	PARSE_XML xmlParser{ xmlText };

	xmlParser.parseXml();

	printf("done\n");
}
