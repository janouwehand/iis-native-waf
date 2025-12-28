#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <httpserv.h>
#include <fstream>
#include <ctime>

//
// Substatus codes (400.x)
//
enum WafSubstatus : USHORT
{
	SUBSTATUS_URL_TOO_LONG = 1001,
	SUBSTATUS_RAW_UNICODE = 1002,
	SUBSTATUS_COLON_IN_PATH = 1003,
	SUBSTATUS_BAD_PERCENT = 1004,
	SUBSTATUS_IP_HOST = 1005
};

static char g_LogPath[MAX_PATH] = "C:\\SimpleWAF.txt"; // fallback

//
// Logging
//
static void LogBlockedUrl(
	const char* rawUrl,
	USHORT urlLen,
	const char* reason,
	const char* remoteIp,
	USHORT ipLen
)
{
	std::ofstream log(
		g_LogPath,
		std::ios::out | std::ios::app | std::ios::binary
	);

	if (!log.is_open())
	{
		return;
	}

	std::time_t now = std::time(nullptr);
	std::tm tm{};
	localtime_s(&tm, &now);

	char timebuf[32];
	std::strftime(timebuf, sizeof(timebuf),
		"%Y-%m-%d %H:%M:%S", &tm);

	log << "[" << timebuf << "] ";

	if (remoteIp && ipLen)
	{
		log << "[IP ";
		log.write(remoteIp, ipLen);
		log << "] ";
	}

	if (reason)
	{
		log << "[" << reason << "] ";
	}

	log.write(rawUrl, urlLen);
	log << "\r\n";
}

//
// Helpers
//
static bool IsIpHost(const char* host, USHORT len)
{
	if (!host || !len)
	{
		return true;
	}

	// IPv6 literal
	if (host[0] == '[')
	{
		return true;
	}

	for (USHORT i = 0; i < len; ++i)
	{
		char c = host[i];

		if (c == ':')
		{
			break; // stop at port
		}

		if ((c >= '0' && c <= '9') || c == '.')
		{
			continue;
		}

		return false; // letter → hostname
	}

	return true; // digits/dots only → IPv4
}

static constexpr bool IsHex(unsigned char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

static bool ValidatePath(
	const unsigned char* p,
	USHORT len,
	const char*& reason,
	USHORT& substatus
)
{
	reason = nullptr;
	substatus = 0;

	if (len > 16384)
	{
		reason = "URL_TOO_LONG";
		substatus = SUBSTATUS_URL_TOO_LONG;
		return false;
	}

	for (USHORT i = 0; i < len; ++i)
	{
		unsigned char c = p[i];

		if (c == '?')
		{
			break;
		}

		if (c >= 0x80)
		{
			reason = "RAW_UNICODE";
			substatus = SUBSTATUS_RAW_UNICODE;
			return false;
		}

		if (c == ':')
		{
			reason = "COLON_IN_PATH";
			substatus = SUBSTATUS_COLON_IN_PATH;
			return false;
		}

		if (c == '%')
		{
			if (i + 2 >= len ||
				!IsHex(p[i + 1]) ||
				!IsHex(p[i + 2]))
			{
				reason = "BAD_PERCENT_ENCODING";
				substatus = SUBSTATUS_BAD_PERCENT;
				return false;
			}
			i += 2;
		}
	}

	return true;
}

static REQUEST_NOTIFICATION_STATUS BlockRequest(
	IHttpContext* ctx,
	HTTP_REQUEST const* req,
	const char* reason,
	USHORT substatus,
	const char* ip,
	USHORT ipLen
)
{
	LogBlockedUrl(req->pRawUrl, req->RawUrlLength, reason, ip, ipLen);

	auto* resp = ctx->GetResponse();
	resp->SetStatus(400, "Bad Request", substatus);
	resp->SetHeader("Content-Length", "0", 1, TRUE);

	return RQ_NOTIFICATION_FINISH_REQUEST;
}

//
// WAF module
//
class SimpleWafModule : public CHttpModule
{
public:
	REQUEST_NOTIFICATION_STATUS OnBeginRequest(
		IHttpContext* ctx,
		IHttpEventProvider*
	)
	{
		auto* request = ctx->GetRequest();
		if (!request)
		{
			return RQ_NOTIFICATION_CONTINUE;
		}

		auto const* req = request->GetRawHttpRequest();
		if (!req || !req->pRawUrl || !req->RawUrlLength)
		{
			return RQ_NOTIFICATION_CONTINUE;
		}

		// Remote IP (IIS authoritative)
		PCSTR ip = nullptr;
		DWORD ipLen = 0;
		ctx->GetServerVariable("REMOTE_ADDR", &ip, &ipLen);

		const auto* p = reinterpret_cast<const unsigned char*>(req->pRawUrl);

		const char* reason = nullptr;

		if (USHORT substatus = 0; !ValidatePath(p, req->RawUrlLength, reason, substatus))
		{
			return BlockRequest(
				ctx,
				req,
				reason,
				substatus,
				ip,
				static_cast<USHORT>(ipLen)
			);
		}

		// Host header enforcement
		USHORT hostLen = 0;

		if (PCSTR host = request->GetHeader("Host", &hostLen); IsIpHost(host, hostLen))
		{
			return BlockRequest(
				ctx,
				req,
				"IP_HOST",
				SUBSTATUS_IP_HOST,
				ip,
				static_cast<USHORT>(ipLen)
			);
		}

		return RQ_NOTIFICATION_CONTINUE;
	}
};

static void InitLogPath()
{
	char buf[MAX_PATH];
	DWORD len = GetEnvironmentVariableA(
		"SIMPLE_WAF_LOG_PATH",
		buf,
		sizeof(buf)
	);

	if (len > 0 && len < sizeof(buf))
	{
		strcpy_s(g_LogPath, buf);
	}
}

//
// Factory
//
class SimpleWafFactory : public IHttpModuleFactory
{
public:
	HRESULT GetHttpModule(
		CHttpModule** ppModule,
		IModuleAllocator*
	)
	{
		*ppModule = new SimpleWafModule();
		return S_OK;
	}

	void Terminate()
	{
		delete this;
	}
};

//
// Entry point
//
extern "C" __declspec(dllexport)
HRESULT __stdcall RegisterModule(
	DWORD,
	IHttpModuleRegistrationInfo* pInfo,
	IHttpServer*
)
{
	InitLogPath();

	return pInfo->SetRequestNotifications(
		new SimpleWafFactory(),
		RQ_BEGIN_REQUEST,
		0
	);
}
