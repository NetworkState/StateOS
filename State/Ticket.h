
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

struct TICKET
{
	using OUTSTREAM = VLSTREAM<SCHEDULER_STACK>;
	struct TK_OBJECT
	{
		TOKEN id;
		TOKEN timestamp;

		void format(OUTSTREAM& outStream, VISUAL_DYANMIC dynamic) const
		{
			outStream.write(dynamic, id);
			if (timestamp)
			{
				outStream.write(outStream.moveCloser(dynamic, 0x10), timestamp);
			}
		}

		static bool parse(TK_OBJECT& object, VLBUFFER& inputBuffer)
		{
			auto result = false;
			if (auto token = inputBuffer.read())
			{
				object.id = token.contour;
				if (auto childToken = inputBuffer.readIfCloser(token))
				{
					object.timestamp = token.contour;
				}
				result = true;
			}
			return result;
		}
	};

	struct TK_IDENTITY
	{
		TOKEN id;
		U512 publicKey;
		DATASTREAM<TK_OBJECT, SERVICE_STACK, 4, 4> objectStream;
		BUFFER privateData;

		void format(OUTSTREAM& outStream, VISUAL_DYANMIC dynamic) const
		{
			outStream.write(dynamic, id);

			dynamic = outStream.moveCloser(dynamic);
			outStream.write(dynamic, ECKEY_TOKEN, publicKey);
			for (auto objects = objectStream.toBuffer(); auto && object: objects)
			{
				object.format(outStream, dynamic);
			}

			outStream.write(dynamic, Blob, privateData);
		}

		static bool parse(TK_IDENTITY& identity, VLBUFFER& inputBuffer)
		{
			auto result = false;
			if (auto idToken = inputBuffer.readIf(TOKEN_ID))
			{

				result = true;
			}
		}
	};

	struct TICKET_HEADER
	{
		TOKEN ticketId;
		TOKEN bankId;
		TOKEN command;
		DATASTREAM<TK_IDENTITY, SERVICE_STACK, 2> identityStream;
		BUFFER extension;
	};

	TICKET_HEADER header;
	DATASTREAM<VLTOKEN, SERVICE_STACK> content;
	BUFFER attachment;

	static void format(TICKET& ticket)
	{
		VISUAL_DYANMIC dynamic{ VI_INVISIBLE, VS_BLOCK };
		VLSTREAM<> dataStream{ dynamic };
		dataStream.write(dynamic, ticket.header.ticketId);
		dataStream.write(dynamic, ticket.header.command);

		for (auto&& identities = ticket.header.identityStream.toBuffer(); auto && identity : identities)
		{
			identity.format(dataStream, dynamic);
		}
	}

	static bool parse(TICKET& ticket, BUFFER ticketData, BUFFER externalData = NULL_BUFFER)
	{
		VLBUFFER ticketBuffer{ ticketData };
		if (ticket.header.ticketId = ticketBuffer.read().contour)
		{

		}
		else DBGBREAK();
	}

	TK_OBJECT& getObject(UINT32 index = 0)
	{
		auto&& identity = header.identityStream.at(0);
		auto&& object = identity.objectStream.at(0);
		return object;
	}
};
