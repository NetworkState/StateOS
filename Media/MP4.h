#pragma once

constexpr UINT32 FOURCC(const char str[]) { return (UINT32)str[0] << 24 | (UINT32)str[1] << 16 | (UINT32)str[2] << 8 | (UINT32)str[3]; }

constexpr auto MAJOR_3gp4 = FOURCC("3gp4");
constexpr auto MAJOR_3gp5 = FOURCC("3gp5");
constexpr auto MAJOR_3gp6 = FOURCC("3gp6");
constexpr auto MAJOR_3gp7 = FOURCC("3gp7");
constexpr auto MAJOR_isml = FOURCC("isml");
constexpr auto MAJOR_isom = FOURCC("isom");
constexpr auto MAJOR_qt__ = FOURCC("qt  ");
constexpr auto MAJOR_dash = FOURCC("dash");
constexpr auto MAJOR_mp41 = FOURCC("mp41");
constexpr auto MAJOR_avc1 = FOURCC("avc1");
constexpr auto MAJOR_M4A  = FOURCC("M4A ");

constexpr auto ATOM_root1 = FOURCC("root");

constexpr auto ATOM_root = FOURCC("root");
constexpr auto ATOM_uuid = FOURCC("uuid");
constexpr auto ATOM_ftyp = FOURCC("ftyp");
constexpr auto ATOM_moov = FOURCC("moov");
constexpr auto ATOM_foov = FOURCC("foov");
constexpr auto ATOM_cmov = FOURCC("cmov");
constexpr auto ATOM_dcom = FOURCC("dcom");
constexpr auto ATOM_cmvd = FOURCC("cmvd");
constexpr auto ATOM_styp = FOURCC("styp");
constexpr auto ATOM_moof = FOURCC("moof");
constexpr auto ATOM_mdat = FOURCC("mdat");
constexpr auto ATOM_skip = FOURCC("skip");
constexpr auto ATOM_free = FOURCC("free");
constexpr auto ATOM_udta = FOURCC("udta");
constexpr auto ATOM_wide = FOURCC("wide");
constexpr auto ATOM_binm2 = FOURCC("\x82\x82\x7f\x7d"); /* binary Computer Graphics Metafile */

constexpr auto ATOM_isom = FOURCC("isom");
constexpr auto ATOM_iso2 = FOURCC("iso2");
constexpr auto ATOM_iso3 = FOURCC("iso3");
constexpr auto ATOM_iso4 = FOURCC("iso4");
constexpr auto ATOM_iso5 = FOURCC("iso5");
constexpr auto ATOM_iso6 = FOURCC("iso6");
constexpr auto ATOM_mp41 = FOURCC("mp41");
constexpr auto ATOM_mp42 = FOURCC("mp42");

constexpr auto ATOM_pnot = FOURCC("pnot");
constexpr auto ATOM_pict = FOURCC("pict");
constexpr auto ATOM_PICT = FOURCC("PICT");
constexpr auto ATOM_data = FOURCC("data");
constexpr auto ATOM_trak = FOURCC("trak");
constexpr auto ATOM_mvhd = FOURCC("mvhd");
constexpr auto ATOM_tkhd = FOURCC("tkhd");
constexpr auto ATOM_tref = FOURCC("tref");
constexpr auto ATOM_load = FOURCC("load");
constexpr auto ATOM_mdia = FOURCC("mdia");
constexpr auto ATOM_mdhd = FOURCC("mdhd");
constexpr auto ATOM_hdlr = FOURCC("hdlr");
constexpr auto ATOM_minf = FOURCC("minf");
constexpr auto ATOM_vmhd = FOURCC("vmhd");
constexpr auto ATOM_smhd = FOURCC("smhd");
constexpr auto ATOM_hmhd = FOURCC("hmhd");
constexpr auto ATOM_dinf = FOURCC("dinf");
constexpr auto ATOM_url  = FOURCC("url ");
constexpr auto ATOM_urn  = FOURCC("urn ");
constexpr auto ATOM_dref = FOURCC("dref");
constexpr auto ATOM_stbl = FOURCC("stbl");
constexpr auto ATOM_stts = FOURCC("stts");
constexpr auto ATOM_ctts = FOURCC("ctts");
constexpr auto ATOM_cslg = FOURCC("cslg");
constexpr auto ATOM_stsd = FOURCC("stsd");
constexpr auto ATOM_stsz = FOURCC("stsz");
constexpr auto ATOM_stz2 = FOURCC("stz2");
constexpr auto ATOM_stsc = FOURCC("stsc");
constexpr auto ATOM_stco = FOURCC("stco");
constexpr auto ATOM_co64 = FOURCC("co64");
constexpr auto ATOM_sbgp = FOURCC("sbgp");
constexpr auto ATOM_sgpd = FOURCC("sgpd");
constexpr auto ATOM_stss = FOURCC("stss");
constexpr auto ATOM_stsh = FOURCC("stsh");
constexpr auto ATOM_stdp = FOURCC("stdp");
constexpr auto ATOM_edts = FOURCC("edts");
constexpr auto ATOM_elst = FOURCC("elst");
constexpr auto ATOM_mvex = FOURCC("mvex");
constexpr auto ATOM_sdtp = FOURCC("sdtp");
constexpr auto ATOM_trex = FOURCC("trex");
constexpr auto ATOM_mehd = FOURCC("mehd");
constexpr auto ATOM_mfhd = FOURCC("mfhd");
constexpr auto ATOM_traf = FOURCC("traf");
constexpr auto ATOM_sidx = FOURCC("sidx");
constexpr auto ATOM_tfhd = FOURCC("tfhd");
constexpr auto ATOM_tfdt = FOURCC("tfdt");
constexpr auto ATOM_trun = FOURCC("trun");
constexpr auto ATOM_cprt = FOURCC("cprt");
constexpr auto ATOM_iods = FOURCC("iods");
constexpr auto ATOM_pasp = FOURCC("pasp");
constexpr auto ATOM_mfra = FOURCC("mfra");
constexpr auto ATOM_mfro = FOURCC("mfro");
constexpr auto ATOM_tfra = FOURCC("tfra");
constexpr auto ATOM_keys = FOURCC("keys");
constexpr auto ATOM_st3d = FOURCC("st3d");
constexpr auto ATOM_sv3d = FOURCC("sv3d");
constexpr auto ATOM_proj = FOURCC("proj");
constexpr auto ATOM_prhd = FOURCC("prhd");
constexpr auto ATOM_cbmp = FOURCC("cbmp");
constexpr auto ATOM_equi = FOURCC("equi");
constexpr auto ATOM_nmhd = FOURCC("nmhd");
constexpr auto ATOM_mp2v = FOURCC("mp2v");
constexpr auto ATOM_mp4v = FOURCC("mp4v");
constexpr auto ATOM_mp4a = FOURCC("mp4a");
constexpr auto ATOM_mp4s = FOURCC("mp4s");
constexpr auto ATOM_vide = FOURCC("vide");
constexpr auto ATOM_soun = FOURCC("soun");
constexpr auto ATOM_hint = FOURCC("hint");
constexpr auto ATOM_hdv2 = FOURCC("hdv2");
constexpr auto ATOM_rrtp = FOURCC("rrtp");
constexpr auto ATOM_dpnd = FOURCC("dpnd");
constexpr auto ATOM_cdsc = FOURCC("cdsc");
constexpr auto ATOM_ipir = FOURCC("ipir");
constexpr auto ATOM_mpod = FOURCC("mpod");
constexpr auto ATOM_hnti = FOURCC("hnti");
constexpr auto ATOM_rtp  = FOURCC("rtp ");
constexpr auto ATOM_btrt = FOURCC("btrt");
constexpr auto ATOM_sdp  = FOURCC("sdp ");
constexpr auto ATOM_tims = FOURCC("tims");
constexpr auto ATOM_tsro = FOURCC("tsro");
constexpr auto ATOM_tssy = FOURCC("tssy");
constexpr auto ATOM_esds = FOURCC("esds");
constexpr auto ATOM_lpcm = FOURCC("lpcm");
constexpr auto ATOM__mp3 = FOURCC(".mp3");
constexpr auto ATOM_ms02 = FOURCC("ms\x0\x02");
constexpr auto ATOM_ms11 = FOURCC("ms\x0\x11");
constexpr auto ATOM_ms55 = FOURCC("ms\x0\x55");
constexpr auto ATOM_twos = FOURCC("twos");
constexpr auto ATOM_sowt = FOURCC("sowt");
constexpr auto ATOM_QDMC = FOURCC("QDMC");
constexpr auto ATOM_QDM2 = FOURCC("QDM2");
constexpr auto ATOM_XiFL = FOURCC("XiFL");
constexpr auto ATOM_XiVs = FOURCC("XiVs");
constexpr auto ATOM_ima4 = FOURCC("ima4");
constexpr auto ATOM_IMA4 = FOURCC("IMA4");
constexpr auto ATOM_dvi  = FOURCC("dvi ");
constexpr auto ATOM_MAC3 = FOURCC("MAC3");
constexpr auto ATOM_MAC6 = FOURCC("MAC6");
constexpr auto ATOM_alaw = FOURCC("alaw");
constexpr auto ATOM_ulaw = FOURCC("ulaw");
constexpr auto ATOM_Qclp = FOURCC("Qclp");
constexpr auto ATOM_samr = FOURCC("samr");
constexpr auto ATOM_sawb = FOURCC("sawb");
constexpr auto ATOM_OggS = FOURCC("OggS");
constexpr auto ATOM_agsm = FOURCC("agsm");
constexpr auto ATOM_alac = FOURCC("alac");
constexpr auto ATOM_AC3  = FOURCC("AC-3");
constexpr auto ATOM_ac3  = FOURCC("ac-3");
constexpr auto ATOM_eac3 = FOURCC("ec-3");
constexpr auto ATOM_dac3 = FOURCC("dac3");
constexpr auto ATOM_dec3 = FOURCC("dec3");
constexpr auto ATOM_ddts = FOURCC("ddts"); /* DTS formats */
constexpr auto ATOM_dtsc = FOURCC("dtsc");
constexpr auto ATOM_dtsh = FOURCC("dtsh");
constexpr auto ATOM_dtsl = FOURCC("dtsl");
constexpr auto ATOM_dtse = FOURCC("dtse");
constexpr auto ATOM_dtsm = FOURCC("dts-");
constexpr auto ATOM_dtsp = FOURCC("dts+");
constexpr auto ATOM_vc1  = FOURCC("vc-1");
constexpr auto ATOM_dvc1 = FOURCC("dvc1");
constexpr auto ATOM_WMA2 = FOURCC("WMA2");
constexpr auto ATOM_wma  = FOURCC("wma ");
constexpr auto ATOM_enda = FOURCC("enda");
constexpr auto ATOM_gnre = FOURCC("gnre");
constexpr auto ATOM_trkn = FOURCC("trkn");
constexpr auto ATOM_chan = FOURCC("chan");
constexpr auto ATOM_in24 = FOURCC("in24");
constexpr auto ATOM_in32 = FOURCC("in32");
constexpr auto ATOM_fl32 = FOURCC("fl32");
constexpr auto ATOM_fl64 = FOURCC("fl64");
constexpr auto ATOM_Opus = FOURCC("Opus");
constexpr auto ATOM_fLaC = FOURCC("fLaC");
constexpr auto ATOM_dfLa = FOURCC("dfLa");

/* XiphQT */
constexpr auto ATOM_fCtS = FOURCC("fCtS");
constexpr auto ATOM_vCtH = FOURCC("vCtH");
constexpr auto ATOM_vCtC = FOURCC("vCtC");
constexpr auto ATOM_vCtd = FOURCC("vCt#");
constexpr auto ATOM_zlib = FOURCC("zlib");
constexpr auto ATOM_SVQ1 = FOURCC("SVQ1");
constexpr auto ATOM_SVQ3 = FOURCC("SVQ3");
constexpr auto ATOM_ZyGo = FOURCC("ZyGo");
constexpr auto ATOM_3IV1 = FOURCC("3IV1");
constexpr auto ATOM_3iv1 = FOURCC("3iv1");
constexpr auto ATOM_3IV2 = FOURCC("3IV2");
constexpr auto ATOM_3iv2 = FOURCC("3iv2");
constexpr auto ATOM_3IVD = FOURCC("3IVD");
constexpr auto ATOM_3ivd = FOURCC("3ivd");
constexpr auto ATOM_3VID = FOURCC("3VID");
constexpr auto ATOM_3vid = FOURCC("3vid");
constexpr auto ATOM_FFV1 = FOURCC("FFV1");
constexpr auto ATOM_h263 = FOURCC("h263");
constexpr auto ATOM_s263 = FOURCC("s263");
constexpr auto ATOM_DIVX = FOURCC("DIVX");
constexpr auto ATOM_XVID = FOURCC("XVID");
constexpr auto ATOM_cvid = FOURCC("cvid");
constexpr auto ATOM_mjpa = FOURCC("mjpa");
constexpr auto ATOM_mjpb = FOURCC("mjqt");
constexpr auto ATOM_mjqt = FOURCC("mjht");
constexpr auto ATOM_mjht = FOURCC("mjpb");
constexpr auto ATOM_VP31 = FOURCC("VP31");
constexpr auto ATOM_vp31 = FOURCC("vp31");
constexpr auto ATOM_h264 = FOURCC("h264");
constexpr auto ATOM_H264 = FOURCC("H264");
constexpr auto ATOM_qdrw = FOURCC("qdrw");
constexpr auto ATOM_vp08 = FOURCC("vp08");
constexpr auto ATOM_vp09 = FOURCC("vp09");
constexpr auto ATOM_vp10 = FOURCC("vp10");
constexpr auto ATOM_WMV3 = FOURCC("WMV3");
constexpr auto ATOM_WVC1 = FOURCC("WVC1");
constexpr auto ATOM_av01 = FOURCC("av01");
constexpr auto ATOM_avc1 = FOURCC("avc1");
constexpr auto ATOM_avc3 = FOURCC("avc3");
constexpr auto ATOM_av1C = FOURCC("av1C");
constexpr auto ATOM_avcC = FOURCC("avcC");
constexpr auto ATOM_vpcC = FOURCC("vpcC");
constexpr auto ATOM_m4ds = FOURCC("m4ds");
constexpr auto ATOM_fiel = FOURCC("fiel");
constexpr auto ATOM_glbl = FOURCC("glbl");
constexpr auto ATOM_hvcC = FOURCC("hvcC");
constexpr auto ATOM_dvc  = FOURCC("dvc ");
constexpr auto ATOM_dvp  = FOURCC("dvp ");
constexpr auto ATOM_dv5n = FOURCC("dv5n");
constexpr auto ATOM_dv5p = FOURCC("dv5p");
constexpr auto ATOM_raw  = FOURCC("raw ");
constexpr auto ATOM_dOps = FOURCC("dOps");
constexpr auto ATOM_wfex = FOURCC("wfex");
constexpr auto ATOM_jpeg = FOURCC("jpeg");
constexpr auto ATOM_yv12 = FOURCC("yv12");
constexpr auto ATOM_yuv2 = FOURCC("yuv2");
constexpr auto ATOM_rmra = FOURCC("rmra");
constexpr auto ATOM_rmda = FOURCC("rmda");
constexpr auto ATOM_rdrf = FOURCC("rdrf");
constexpr auto ATOM_rmdr = FOURCC("rmdr");
constexpr auto ATOM_rmvc = FOURCC("rmvc");
constexpr auto ATOM_rmcd = FOURCC("rmcd");
constexpr auto ATOM_rmqu = FOURCC("rmqu");
constexpr auto ATOM_alis = FOURCC("alis");

constexpr auto ATOM_gmhd = FOURCC("gmhd");
constexpr auto ATOM_wave = FOURCC("wave");
constexpr auto ATOM_strf = FOURCC("strf");
constexpr auto ATOM_drms = FOURCC("drms");
constexpr auto ATOM_sinf = FOURCC("sinf");
constexpr auto ATOM_schi = FOURCC("schi");
constexpr auto ATOM_user = FOURCC("user");
constexpr auto ATOM_key  = FOURCC("key ");
constexpr auto ATOM_iviv = FOURCC("iviv");
constexpr auto ATOM_mean = FOURCC("mean");
constexpr auto ATOM_name = FOURCC("name");
constexpr auto ATOM_priv = FOURCC("priv");
constexpr auto ATOM_drmi = FOURCC("drmi");
constexpr auto ATOM_frma = FOURCC("frma");
constexpr auto ATOM_skcr = FOURCC("skcr");
constexpr auto ATOM_ASF  = FOURCC("ASF ");
constexpr auto ATOM_text = FOURCC("text");
constexpr auto ATOM_tx3g = FOURCC("tx3g");
constexpr auto ATOM_subp = FOURCC("subp");
constexpr auto ATOM_subt = FOURCC("subt");
constexpr auto ATOM_sbtl = FOURCC("sbtl");
constexpr auto ATOM_clcp = FOURCC("clcp");
constexpr auto ATOM_c608 = FOURCC("c608");
constexpr auto ATOM_c708 = FOURCC("c708");
constexpr auto ATOM_wvtt = FOURCC("wvtt");

/* In sample for WebVTT */
constexpr auto ATOM_vttc = FOURCC("vttc");
constexpr auto ATOM_payl = FOURCC("payl");

constexpr auto ATOM_0xa9nam = FOURCC("\xa9nam");
constexpr auto ATOM_0xa9aut = FOURCC("\xa9\x61ut");
constexpr auto ATOM_0xa9cpy = FOURCC("\xa9\x63py");
constexpr auto ATOM_0xa9inf = FOURCC("\xa9inf");
constexpr auto ATOM_0xa9isr = FOURCC("\xa9isr");
constexpr auto ATOM_0xa9lab = FOURCC("\xa9lab");
constexpr auto ATOM_0xa9lal = FOURCC("\xa9lal");
constexpr auto ATOM_0xa9ART = FOURCC("\xa9\x41RT");
constexpr auto ATOM_0xa9des = FOURCC("\xa9\x64\x65s");
constexpr auto ATOM_0xa9dir = FOURCC("\xa9\x64ir");
constexpr auto ATOM_0xa9cmt = FOURCC("\xa9\x63mt");
constexpr auto ATOM_0xa9req = FOURCC("\xa9req");
constexpr auto ATOM_0xa9day = FOURCC("\xa9\x64\x61y");
constexpr auto ATOM_0xa9fmt = FOURCC("\xa9\x66mt");
constexpr auto ATOM_0xa9prd = FOURCC("\xa9prd");
constexpr auto ATOM_0xa9prf = FOURCC("\xa9prf");
constexpr auto ATOM_0xa9src = FOURCC("\xa9src");
constexpr auto ATOM_0xa9alb = FOURCC("\xa9\x61lb");
constexpr auto ATOM_0xa9dis = FOURCC("\xa9\x64is");
constexpr auto ATOM_0xa9enc = FOURCC("\xa9\x65nc");
constexpr auto ATOM_0xa9trk = FOURCC("\xa9trk");
constexpr auto ATOM_0xa9url = FOURCC("\xa9url");
constexpr auto ATOM_0xa9dsa = FOURCC("\xa9\x64sa");
constexpr auto ATOM_0xa9hst = FOURCC("\xa9hst");
constexpr auto ATOM_0xa9ope = FOURCC("\xa9ope");
constexpr auto ATOM_0xa9wrt = FOURCC("\xa9wrt");
constexpr auto ATOM_0xa9com = FOURCC("\xa9\x63om");
constexpr auto ATOM_0xa9too = FOURCC("\xa9too");
constexpr auto ATOM_0xa9wrn = FOURCC("\xa9wrn");
constexpr auto ATOM_0xa9swr = FOURCC("\xa9swr");
constexpr auto ATOM_0xa9mak = FOURCC("\xa9mak");
constexpr auto ATOM_0xa9mal = FOURCC("\xa9mal");
constexpr auto ATOM_0xa9mod = FOURCC("\xa9mod");
constexpr auto ATOM_0xa9PRD = FOURCC("\xa9PRD");
constexpr auto ATOM_0xa9grp = FOURCC("\xa9grp");
constexpr auto ATOM_0xa9lyr = FOURCC("\xa9lyr");
constexpr auto ATOM_0xa9gen = FOURCC("\xa9gen");
constexpr auto ATOM_0xa9st3 = FOURCC("\xa9st3");
constexpr auto ATOM_0xa9ard = FOURCC("\xa9\x61rd");
constexpr auto ATOM_0xa9arg = FOURCC("\xa9\x61rg");
constexpr auto ATOM_0xa9cak = FOURCC("\xa9\x63\x61k");
constexpr auto ATOM_0xa9con = FOURCC("\xa9\x63on");
constexpr auto ATOM_0xa9lnt = FOURCC("\xa9lnt");
constexpr auto ATOM_0xa9phg = FOURCC("\xa9phg");
constexpr auto ATOM_0xa9pub = FOURCC("\xa9pub");
constexpr auto ATOM_0xa9sne = FOURCC("\xa9sne");
constexpr auto ATOM_0xa9snm = FOURCC("\xa9snm");
constexpr auto ATOM_0xa9sol = FOURCC("\xa9sol");
constexpr auto ATOM_0xa9thx = FOURCC("\xa9thx");
constexpr auto ATOM_0xa9xpd = FOURCC("\xa9xpd");
constexpr auto ATOM_0xa9xyz = FOURCC("\xa9xyz");
constexpr auto ATOM_aART = FOURCC("aART");
constexpr auto ATOM_chpl = FOURCC("chpl");
constexpr auto ATOM_HMMT = FOURCC("HMMT");
constexpr auto ATOM_desc = FOURCC("desc");
constexpr auto ATOM_disk = FOURCC("disk");
constexpr auto ATOM_ID32 = FOURCC("ID32");
constexpr auto ATOM_WLOC = FOURCC("WLOC");
constexpr auto ATOM_ITUN = FOURCC("----");

constexpr auto ATOM_meta = FOURCC("meta");
constexpr auto ATOM_atID = FOURCC("atID");
constexpr auto ATOM_ilst = FOURCC("ilst");
constexpr auto ATOM_cnID = FOURCC("cnID");
constexpr auto ATOM_covr = FOURCC("covr");
constexpr auto ATOM_flvr = FOURCC("flvr");
constexpr auto ATOM_rtng = FOURCC("rtng");
constexpr auto ATOM_tsel = FOURCC("tsel");
constexpr auto ATOM_xid_ = FOURCC("xid ");
constexpr auto ATOM_gshh = FOURCC("gshh");
constexpr auto ATOM_gspm = FOURCC("gspm");
constexpr auto ATOM_gspu = FOURCC("gspu");
constexpr auto ATOM_gssd = FOURCC("gssd");
constexpr auto ATOM_gsst = FOURCC("gsst");
constexpr auto ATOM_gstd = FOURCC("gstd");
constexpr auto ATOM_colr = FOURCC("colr");
constexpr auto ATOM_SmDm = FOURCC("SmDm");
constexpr auto ATOM_CoLL = FOURCC("CoLL");

constexpr auto ATOM_0x40PRM = FOURCC("@PRM");
constexpr auto ATOM_0x40PRQ = FOURCC("@PRQ");
constexpr auto ATOM_chap = FOURCC("chap");
constexpr auto ATOM_MCPS = FOURCC("MCPS");
constexpr auto ATOM_SDLN = FOURCC("SDLN");
constexpr auto ATOM_vndr = FOURCC("vndr");

constexpr auto ATOM_SA3D = FOURCC("SA3D");

constexpr auto HANDLER_mdta = FOURCC("mdta");
constexpr auto HANDLER_mdir = FOURCC("mdir");

constexpr auto SAMPLEGROUP_rap = FOURCC("rap ");

USTRING PrintAtom(UINT32 type)
{
	auto&& stream = ByteStream(8);
	stream.writeByte((UINT8)(type >> 24));
	stream.writeByte((UINT8)(type >> 16));
	stream.writeByte((UINT8)(type >> 8));
	stream.writeByte((UINT8)(type >> 0));

	return stream.toBuffer();
}

struct ATOM_HEADER
{
	UINT32 name;
	UINT32 length; 
};

using LEAF_ATOM_HANDLER = void (*)(UINT32 atom, BUFFER data);
using CONTAINER_ATOM_HANDLER = void (*)(UINT32 atom, UINT32 length);

template <typename STACK>
struct MP4_READER
{
	struct SAMPLE_INFO
	{
		UINT32 decodeTime;
		UINT32 presentationOffset;
		UINT32 size;
		bool isKeyFrame;
		UINT64 fileOffset;
	};

	struct TRACK_INFO
	{
		UINT32 trackId;

		UINT32 handler;
		UINT32 duration;
		UINT32 timeScale;
		UINT32 codec;

		UINT32 height;
		UINT32 width;
		UINT32 volume;

		BYTESTREAM codecData;
		DATASTREAM<SAMPLE_INFO, STACK, 2> sampleStream;

		explicit operator bool() { return IsValidRef(*this) && trackId != 0; }
	};

	//TRACK_INFO& trackInfo;
	//STACK sessionStack;

	DATASTREAM<TRACK_INFO, STACK, 4> trackInfoStream;

	FILE_STREAM fileStream;
	//MP4_READER(SCHEDULER& schedulerArg) : scheduler(schedulerArg), fileStream(schedulerArg), 
		//sessionStack(32 * 1024 * 1024, 0) {}

	constexpr static UINT32 LeafAtoms[] = { ATOM_ftyp, ATOM_mvhd, ATOM_tkhd, ATOM_mdhd, ATOM_hdlr, ATOM_vmhd, ATOM_dref, ATOM_stss, ATOM_stsd,
		ATOM_stts, ATOM_stsz, ATOM_stco, ATOM_edts, ATOM_elst, ATOM_load, ATOM_tref, ATOM_ctts, ATOM_stsc, ATOM_smhd, ATOM_sgpd, ATOM_sbgp,
		ATOM_meta, ATOM_ilst};

	bool isLeafAtom(UINT32 atomType)
	{
		auto matchFound = false;
		for (UINT32 i = 0; i < _countof(LeafAtoms); i++)
		{
			if (LeafAtoms[i] == atomType)
			{
				matchFound = true;
				break;
			}
		}
		return matchFound;
	}

	UINT8 getVersion(BUFFER& data)
	{
		auto version = data.readByte();
		data.shift(3);
		return version;
	}

	UINT64 getTime(UINT8 revision, BUFFER& data)
	{
		UINT64 value;
		value = revision == 1 ? data.readBE64() : data.readBE32();

		if (value > 0) value = MP4ToSystemTime(value * 1000);

		return value;
	}

	UINT32 getDuration(UINT64 value, UINT32 scale)
	{
		auto seconds = value / scale;
		auto milliseconds = ((value % scale) * 1000) / scale;

		return (UINT32)((seconds * 1000) + milliseconds);
	}

	UINT32 getDuration(UINT8 revision, UINT32 scale, BUFFER& data)
	{
		ASSERT(scale > 0);
		UINT64 value = revision == 1 ? data.readBE64() : data.readBE32();
		return getDuration(value, scale);
	}

	BUFFER readString(BUFFER data)
	{
		auto length = data.readByte();
		return data.readBytes(length);
	}

	void parseVideo(TRACK_INFO& trackInfo, UINT32 fourcc, BUFFER data)
	{
		data.shift(16);

		auto width = data.readBE16();
		auto height = data.readBE16();

		auto horizontalResolution = data.readBE32();
		auto verticalResolution = data.readBE32();

		data.shift(4);

		auto frames = data.readBE16();
		auto codecName = readString(data.readBytes(32));

		auto depth = data.readBE16();
		data.shift(2);

		while (data)
		{
			auto atom = readAtom(data);
			LogInfo("Video atom:", PrintAtom(atom.type));

			if (atom.type == ATOM_avcC)
			{
				trackInfo.codecData.writeBytes(atom.data);
			}
		}
	}

	struct TAG_INFO
	{
		UINT8 id;
		BUFFER data;
	};

	constexpr static UINT8 TAG_ES = 3;
	constexpr static UINT8 TAG_CODEC_DESC = 4;
	constexpr static UINT8 TAG_CODEC_PRIVATE = 5;

	TAG_INFO readTag(BUFFER& data)
	{
		auto id = data.readByte();

		UINT32 length = 0;
		for (UINT32 i = 0; i < 4; i++)
		{
			auto byte = data.readByte();
			length = (length << 7) | (byte & 0x7F);
			if ((byte & 0x80) == 0) break;
		}

		return { id, data.readBytes(length) };
	}

	void parseAudio(TRACK_INFO& trackInfo, UINT32 fourcc, BUFFER data)
	{
		auto version = data.readBE16();
		data.shift(6);

		auto channelCount = data.readBE16();
		auto sampleSize = data.readBE16();
		data.shift(4);

		auto sampleRate = data.readBE32() >> 16;

		while (data)
		{
			auto atom = readAtom(data);
			LogInfo("Audio atom:", PrintAtom(atom.type));
			if (atom.type == ATOM_esds)
			{
				getVersion(atom.data);
				auto tag = readTag(atom.data);

				if (tag.id == TAG_ES)
				{
					auto id = tag.data.readBE16();
					auto flags = tag.data.readByte();

					if (flags & 0x80)
					{
						tag.data.readBE16();
					}
					if (flags & 0x40)
					{
						UINT8 len = tag.data.readByte();
						tag.data.shift(len);
					}
					if (flags & 0x20)
					{
						tag.data.readBE16();
					}

					auto descTag = readTag(tag.data);
					if (descTag.id == TAG_CODEC_DESC)
					{
						auto codecId = descTag.data.readByte();
						auto streamType = descTag.data.readByte();
						auto bufferSize = descTag.data.readBE24();
						auto maxBitRate = descTag.data.readBE32();
						auto averageBitRate = descTag.data.readBE32();

						auto codecPrivateTag = readTag(descTag.data);
						ASSERT(codecPrivateTag.id == TAG_CODEC_PRIVATE);
						trackInfo.codecData.writeBytes(codecPrivateTag.data);
					}
				}
			}
		}
	}

	UINT32 timeScale; // in microseconds
	UINT32 duration; // in milliseconds

	void processLeafAtom(UINT32 atomType, BUFFER atomData)
	{
		LogInfo("Leaf Atom: ", PrintAtom(atomType), " Length: ", atomData.length());
		if (atomType == ATOM_ftyp)
		{
			auto majorBrand = atomData.readBE32();
			ASSERT(majorBrand == ATOM_isom);

			auto version = atomData.readBE32();
			while (atomData)
			{
				auto brand = atomData.readBE32();
				LogInfo("Brand: ", PrintAtom(brand));
			}
		}
		else if (atomType == ATOM_mvhd)
		{
			auto version = getVersion(atomData);
			getTime(version, atomData);
			getTime(version, atomData);
			timeScale = atomData.readBE32();// getTimeUnit(atomData);
		}
		else if (atomType == ATOM_meta)
		{

		}
		else DBGBREAK();
	 }

	UINT32 getSampleCount(BUFFER atomData)
	{
		auto count = atomData.readBE32();

		UINT32 sampleCount = 0;
		for (UINT32 i = 0; i < count; i++)
		{
			sampleCount += atomData.readBE32();
			atomData.readBE32();
		}
		return sampleCount;
	}

	struct ATOM_INFO
	{
		UINT8 version;
		UINT32 type;
		BUFFER data;

		ATOM_INFO(UINT32 typeArg, BUFFER dataArg, UINT8 versionArg = 0) : type(typeArg), data(dataArg), version(versionArg) {}
		bool match(UINT32 value) const { return type == value; }
		explicit operator bool() const { return IsValidRef(*this) && data; } 
	};

	DATASTREAM<ATOM_INFO, STACK, 16> atomStream;

	ATOM_INFO readAtom(BUFFER& data)
	{
		ASSERT(data.length() >= 8);

		auto length = data.readBE32();
		auto atomType = data.readBE32();

		ASSERT(length >= 8);
		return { atomType, data.readBytes(length - 8) };
	}

	void getMetadata(TRACK_INFO& trackInfo, STREAM_READER<const ATOM_INFO> atoms)
	{
		do
		{
			{
				auto&& mdhd = atoms.find(ATOM_mdhd);
				VERIFY(mdhd);

				auto data = mdhd.data;
				getTime(mdhd.version, data);
				getTime(mdhd.version, data);

				trackInfo.timeScale = data.readBE32();

				trackInfo.duration = getDuration(mdhd.version, trackInfo.timeScale, data);
			}
			{
				auto&& tkhd = atoms.find(ATOM_tkhd);
				VERIFY(tkhd);

				auto data = tkhd.data;
				getTime(tkhd.version, data);
				getTime(tkhd.version, data);

				trackInfo.trackId = data.readBE32();
				data.shift(4);

				trackInfo.duration = getDuration(tkhd.version, timeScale, data);
				data.shift(50);

				trackInfo.width = data.readBE32();
				trackInfo.height = data.readBE32();
			}
			{
				auto&& hdlr = atoms.find(ATOM_hdlr);
				VERIFY(hdlr);

				auto data = hdlr.data;
				data.shift(4);
				trackInfo.handler = data.readBE32();
				LogInfo("Handler: ", PrintAtom(trackInfo.handler));
			}
			{
				auto&& stsd = atoms.find(ATOM_stsd);
				VERIFY(stsd);

				auto data = stsd.data;
				auto stsdEntries = data.readBE32();
				for (UINT32 i = 0; i < stsdEntries; i++)
				{
					auto fourcc = readAtom(data);
					LogInfo("stsd, fourcc:", PrintAtom(fourcc.type));
					trackInfo.codec = fourcc.type;
					fourcc.data.shift(8);
					if (trackInfo.handler == ATOM_vide)
						parseVideo(trackInfo, fourcc.type, fourcc.data);
					else if (trackInfo.handler == ATOM_soun)
						parseAudio(trackInfo, fourcc.type, fourcc.data);
					else DBGBREAK();
				}
			}
		} while (false);
	}

	struct CHUNK_INFO
	{
		UINT32 sampleStart;
		UINT32 sampleCount;
		UINT64 fileOffset;
	};

	void parseTRAK(BUFFER trakData)
	{
		atomStream.clear();

		auto& trackInfo = trackInfoStream.append();
		while (trakData)
		{
			auto length = trakData.readBE32();
			ASSERT(length >= 8);
			length -= 8;

			auto atomType = trakData.readBE32();
			LogInfo("TRAK atom:", PrintAtom(atomType), ", Length:", length);
			if (isLeafAtom(atomType))
			{
				auto atomData = trakData.readBytes(length);
				auto version = getVersion(atomData);
				atomStream.append(atomType, atomData.rebase(), version);
			}
		}

		do
		{
			auto atoms = atomStream.toBuffer();

			getMetadata(trackInfo, atoms);

			{
				auto&& stts = atoms.find(ATOM_stts);
				VERIFY(stts);

				auto atomData = stts.data;
				auto sampleCount = getSampleCount(atomData);
				trackInfo.sampleStream.commit(sampleCount + 1);

				auto count = atomData.readBE32();

				UINT32 sampleIndex = 0;
				UINT64 decodeTime = 0;
				for (UINT32 i = 0; i < count; i++)
				{
					auto entries = atomData.readBE32();
					auto delta = atomData.readBE32();

					for (UINT32 j = 1; j <= entries; j++)
					{
						auto& sampleInfo = trackInfo.sampleStream.at(sampleIndex + j);
						sampleInfo.decodeTime = getDuration(decodeTime, trackInfo.timeScale);
						//LogInfo("decodeTime, index=", sampleIndex + j, ", time=", sampleInfo.decodeTime);
						decodeTime += delta;
					}
					sampleIndex += entries;
				}
			}
			{
				auto&& ctts = atoms.find(ATOM_ctts);
				if (ctts)
				{
					auto atomData = ctts.data;
					auto count = atomData.readBE32();
					LogInfo("ctts: ", count);

					ASSERT(ctts.version == 0);

					auto sampleId = 0;
					for (UINT32 i = 0; i < count; i++)
					{
						auto sampleCount = atomData.readBE32();
						auto sampleOffset = atomData.readBE32();
						for (UINT32 j = 1; j <= sampleCount; j++)
						{
							auto& sampleInfo = trackInfo.sampleStream.atOrAppend(sampleId + j);
							sampleInfo.presentationOffset = getDuration(sampleOffset, trackInfo.timeScale);
							//LogInfo("ctts, index=", sampleId + j, ", time=", sampleInfo.presentationOffset);
						}
						sampleId += sampleCount;
						//LogInfo("count: ", sampleCount, ", offset: ", sampleOffset);
					}
				}
			}
			{
				auto&& stsz = atoms.find(ATOM_stsz);
				VERIFY(stsz);

				auto atomData = stsz.data;
				auto defaultSize = atomData.readBE32();
				auto count = atomData.readBE32();

				LogInfo("stsz: ", count);
				for (UINT32 i = 1; i <= count; i++)
				{
					auto size = atomData.readBE32();
					trackInfo.sampleStream.at(i).size = size;
					//LogInfo("size: ", size);
				}
			}
			STREAM_BUILDER<CHUNK_INFO, SCHEDULER_STACK, 2> chunkStream;
			{
				auto&& stco = atoms.find(ATOM_stco); // co64
				auto&& co64 = atoms.find(ATOM_co64);

				auto atomData = stco ? stco.data : co64.data;

				auto count = atomData.readBE32();
				LogInfo("stco: ", count);
				chunkStream.commit(count + 1);
				for (UINT32 i = 1; i <= count; i++)
				{
					UINT64 fileOffset = co64 ? atomData.readBE64() : atomData.readBE32();
					chunkStream.at(i).fileOffset = fileOffset;
					//trackInfo.sampleStream.at(i).fileOffset = fileOffset;
				}
			}
			{
				auto&& stsc = atoms.find(ATOM_stsc);
				VERIFY(stsc);

				auto atomData = stsc.data;
				auto count = atomData.readBE32();

				UINT32 lastChunk = 1;
				UINT32 lastCount = 0;
				UINT32 sampleIndex = 1;
				for (UINT32 i = 0; i < count; i++)
				{
					auto firstChunk = atomData.readBE32();
					auto sampleCount = atomData.readBE32();
					auto descriptor = atomData.readBE32();

					for (UINT32 j = lastChunk; j < firstChunk; j++)
					{
						chunkStream.at(j).sampleCount = lastCount;
						chunkStream.at(j).sampleStart = sampleIndex;
						sampleIndex += lastCount;
					}
					lastChunk = firstChunk;
					lastCount = sampleCount;
				}
				for (UINT32 j = lastChunk; j < chunkStream.getCount(); j++)
				{
					chunkStream.at(j).sampleCount = lastCount;
					chunkStream.at(j).sampleStart = sampleIndex;
					sampleIndex += lastCount;
				}
			}

			auto chunks = chunkStream.toBuffer();
			chunks.shift(); // we start at index 1
			for (auto&& chunk : chunks)
			{
				auto fileOffset = chunk.fileOffset;
				for (UINT32 i = 0; i < chunk.sampleCount; i++)
				{
					auto&& sample = trackInfo.sampleStream.at(chunk.sampleStart + i);
					sample.fileOffset = fileOffset;
					fileOffset += sample.size;
				}
			}
		} while (false);

	}
	
	void processContainerAtom(UINT32 atom, UINT64 length)
	{
		LogInfo("Container Atom: ", PrintAtom(atom), " Length: ", length);
		if (atom == ATOM_mdat)
		{
			ASSERT(length > 1);
			auto newFileOffset = fileStream.getFileOffset() + (UINT64)length;
			fileStream.seek(newFileOffset);
		}
		else if (atom == ATOM_trak)
		{
			fileStream.read((UINT32)length, [](PVOID context, NTSTATUS, STASK_ARGV argv)
				{
					auto&& mp4Reader = *(MP4_READER<SCHEDULER> *)context;
					auto&& data = argv.read<BUFFER>(0);
					ASSERT(data);
					if (data)
					{
						mp4Reader.parseTRAK(data);
					}
					mp4Reader.readAtom();
				}, this);
		}
		else
		{
			readAtom();
		}
	}

	void readAtom()
	{
		if (fileStream.atEOF())
		{
			DBGBREAK();
			return;
		}

		fileStream.read(8, [](PVOID context, NTSTATUS, STASK_ARGV argv)
			{
				auto&& mp4Reader = *(MP4_READER<SCHEDULER> *)context;
				auto&& data = argv.read<BUFFER>(0);
				if (data)
				{
					auto length = data.readBE32();
					ASSERT(length >= 8);
					auto atomType = data.readBE32();
					length -= 8;

					if (length > 0)
					{
						if (mp4Reader.isLeafAtom(atomType))
						{
							mp4Reader.fileStream.read(length, [](PVOID context, NTSTATUS, STASK_ARGV argv)
								{
									auto&& mp4Reader = *(MP4_READER<SCHEDULER> *)context;
									auto atomType = argv.read<UINT32>(0);
									auto&& data = argv.read<BUFFER>(1);
									if (data)
									{
										mp4Reader.processLeafAtom(atomType, data);
										mp4Reader.readAtom();
									}
								}, &mp4Reader, atomType);
						}
						else
						{
							if (length == 1)
							{
								mp4Reader.fileStream.read(8, [](PVOID context, NTSTATUS, STASK_ARGV argv)
									{
										auto&& mp4Reader = *(MP4_READER<SCHEDULER> *)context;
										auto atomType = argv.read<UINT32>(0);
										auto&& data = argv.read<BUFFER>(1);
										if (data)
										{
											auto length = data.readBE64();
											mp4Reader.processContainerAtom(atomType, length);
											//mp4Reader.readAtom();
										}
									}, &mp4Reader, atomType);
							}
							else
							{
								mp4Reader.processContainerAtom(atomType, (UINT64)length);
								//mp4Reader.readAtom();
							}
						}
					}
					else
					{
						mp4Reader.readAtom();
					}
				}
			}, this);
	}

	NTSTATUS open(USTRING filename)
	{
		auto status = fileStream.open(filename);
		ASSERT(NT_SUCCESS(status));
		return status;
	}

	void importData()
	{
		readAtom();
	}
};