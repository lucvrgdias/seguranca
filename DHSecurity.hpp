/*
 * DHSecurity.hpp
 *
 *  Created on: Dec 27, 2018
 *      Author: lucas
 */

#ifndef DHSECURITY_HPP_
#define DHSECURITY_HPP_

#include <sqlite3.h>
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/config.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/config.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>
#include <cryptopp/hrtimer.h>
#include <cryptopp/sha.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/asn.h>
#include <cryptopp/rsa.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>
#include <cryptopp/asn.h>
#include <cryptopp/files.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/pssr.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/dh.h>
using namespace CryptoPP;
#include <iostream>
#include <sstream>
using namespace std;
#include <boost/asio.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/array.hpp>
#include <boost/exception/exception.hpp>

#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
using boost::lambda::var;
using boost::lambda::_1;
using namespace boost::asio::ip;
using namespace boost::asio;
typedef unique_ptr<CryptoPP::PK_Verifier> PK_VerifierPtr;
///pkcs1 11 RSA-SHA256 sha256WithRSAEncryption link reference: https://github.com/guanzhi/GmSSL/blob/master/crypto/objects/objects.txt
///Verification of the signature sha256 algorithm according to the OID of the algorithm. Defined in the ASN1 structure that the X509
DEFINE_OID(CryptoPP::ASN1::pkcs_1()+11, sha256withRSAEncryption);
///Verification of the signature md5 algorithm according to the OID of the algorithm. Defined in the ASN1 structure that the X509
DEFINE_OID(CryptoPP::ASN1::pkcs_1()+4, md5withRSAEncryption);

///Verification of the signature sha1 algorithm according to the OID of the algorithm. Defined in the ASN1 structure that the X509
DEFINE_OID(CryptoPP::ASN1::pkcs_1()+5, sha1withRSAEncryption);
#include <boost/asio/connect.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/write.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>

using boost::asio::deadline_timer;
using boost::asio::ip::tcp;
using boost::lambda::bind;
using boost::lambda::var;
using boost::lambda::_1;


/*
 * Socket Client
 */
class Client
{
public:
	Client(string IP, int port)
: socket_(io_service_)
{
		this->IP=IP;
		this->port=port;
}

	bool connect()
	{
		boost::system::error_code ec = boost::asio::error::would_block;
		tcp::endpoint end(ip::address::from_string(IP, ec), port);
		tcp::resolver::iterator iter = tcp::resolver(io_service_).resolve(end);
		boost::asio::async_connect(socket_, iter, var(ec) = _1);
		do io_service_.run_one(); while (ec == boost::asio::error::would_block);
		if (ec || !socket_.is_open())
			return false;
		return true;
	}

	std::string read_line()
	{
		boost::array<char, 4096> aux;
		boost::system::error_code ec = boost::asio::error::would_block;
		socket_.read_some(boost::asio::buffer(aux),ec);
		if (ec)
			throw boost::system::system_error(ec);
		std::string line;
		for(auto it = aux.begin(); it<aux.end()&& *it!='\0';++it)
			line.push_back(*it);
		return line;
	}

	void write_line( std::string line)
	{
		line.push_back('\n');
		line.push_back('\0');
		boost::system::error_code ec = boost::asio::error::would_block;
		socket_.write_some(boost::asio::buffer(line),ec);
		if (ec)
			throw boost::system::system_error(ec);
	}
	void close()
	{
		try
		{
			socket_.close();
		}
		catch(std::exception &e)
		{
			cout << e.what() << endl;
		}
	}
private :
	boost::asio::io_service io_service_;
	tcp::socket socket_;
	boost::asio::streambuf input_buffer_;
	string IP;
	int port;
};


/*
 * Class that applies Hash
 */
class HASHER
{
private :
	string IN, OUT;
public :
	HASHER(string IN)
{
		this->IN=IN;
}
	template <class T>
	string generateHash()
	{
		this->OUT.clear();
		if(std::is_same<T,CryptoPP::Weak1::MD5>::value)
		{
			byte digest[CryptoPP::Weak1::MD5::DIGESTSIZE];
			CryptoPP::Weak1::MD5 hash;
			hash.CalculateDigest(digest,(const byte *)this->IN.data(), this->IN.size());
			this->OUT.append(reinterpret_cast<const char *>(digest),sizeof(digest) );
			return this->OUT;
		}
		if(std::is_same<T,CryptoPP::SHA256>::value || std::is_same<T,CryptoPP::SHA512>::value )
		{
			byte digest[T::DIGESTSIZE];
			T	hash ;
			hash.Update(( byte *)this->IN.c_str(), this->IN.length());
			hash.Final(digest);
			//std::cout << digest << std::endl;
			this->OUT.append(reinterpret_cast<const char *>(digest),sizeof(digest) );
			return this->OUT;
		}
		return this->OUT;

	}
	~HASHER()
	{
		IN.clear();
		OUT.clear();
	}
};



/*
 * Socket Server
 */
class Server
{
	int port;
	boost::asio::io_service io_service_;
	tcp::socket socket;
	tcp::acceptor *acceptor;
	boost::asio::streambuf input_buffer;

public :
	Server(int port) : socket(io_service_)
{
		this->port=port;
		acceptor =  new tcp::acceptor(io_service_, tcp::endpoint(tcp::v4(), this->port) );
}
	bool open()
	{
		try
		{
			boost::system::error_code ec;
			acceptor->accept(socket,ec );
			return true;
		}
		catch(std::exception &e)
		{
			cout<< e.what() << endl;
			return false;
		}
	}
	std::string read_line()
	{
		boost::array<char, 4096> aux;
		boost::system::error_code ec = boost::asio::error::would_block;
		socket.read_some(boost::asio::buffer(aux),ec);
		if (ec)
			throw boost::system::system_error(ec);
		std::string line;
		for(auto it = aux.begin(); it<aux.end()&& *it!='\0';++it)
			line.push_back(*it);
		return line;
	}

	void write_line( std::string line)
	{
		line.push_back('\n');
		line.push_back('\0');
		boost::system::error_code ec = boost::asio::error::would_block;
		socket.write_some(boost::asio::buffer(line),ec);
		if (ec)
			throw boost::system::system_error(ec);
	}
	void close()
	{
		try
		{
			socket.close();
		}
		catch(std::exception &e)
		{
			cout << e.what() << endl;
		}
	}
};

/*
 * class handling digital certificate and operations related to asymmetric cryptography
 */
class Keys
{
private :
	string filePriv, fileCERT, fileCRL;
	RSA::PrivateKey priv;
	RSA::PublicKey pub;
	//CryptoPP::RandomPool rng;
	ByteQueue pub_aux;
	void extractPrivateKey()
	{
		ByteQueue queue;
		string priv_aux;
		FileSource file(filePriv.c_str(), true,  new StringSink(priv_aux));
		queue.Put((byte *)priv_aux.data(), priv_aux.length());
		priv.Load(queue);
		//priv.BERDecodePrivateKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());
	}

	void GetPublicKeyFromCert(CryptoPP::BufferedTransformation & certin)
	{
		string st, str, issuer, date , date2, publick;
		stringstream oss;
		OID sigAlgOID;
		BERSequenceDecoder x509Cert(certin);
		BERSequenceDecoder tbsCert(x509Cert);
		// ASN.1 from RFC 3280
		// TBSCertificate  ::=  SEQUENCE  {
		// version         [0]  EXPLICIT Version DEFAULT v1,
		// consume the context tag on the version
		BERGeneralDecoder context(tbsCert,0xa0);
		word32 ver;
		// only want a v3 cert
		BERDecodeUnsigned<word32>(context,ver,INTEGER,2,2);
		// serialNumber         CertificateSerialNumber,
		Integer serial;
		serial.BERDecode(tbsCert);
		// signature            AlgorithmIdentifier,
		BERSequenceDecoder sigAlg(x509Cert);
		sigAlg.SkipAll();
		//	BERSequenceDecoder signature(tbsCert);
		//	signature.SkipAll();
		ByteQueue d;
		// issuer               Name,
		BERSequenceDecoder issuerName(tbsCert);
		issuerName.SkipAll();
		// validity             Validity,
		BERSequenceDecoder validity(tbsCert);
		byte val[sizeof(validity)];
		validity.CopyTo(d,sizeof(validity));
		d.Get(val, sizeof(d));
		oss  << val;
		date= oss.str();
		date2.append(date);
		date2.erase(date2.begin()+14, date2.end());
		date2.erase(0,2);
		date.erase(0, 17);
		date.erase(date.begin()+12, date.end());
		validity.SkipAll();
		BERSequenceDecoder subjectName(tbsCert);
		subjectName.SkipAll();
		BERSequenceDecoder spki(tbsCert);
		DERSequenceEncoder spkiEncoder(this->pub_aux);
		spki.CopyTo(spkiEncoder);
		spkiEncoder.MessageEnd();

		spki.SkipAll();
		tbsCert.SkipAll();
		x509Cert.SkipAll();
		this->pub.Load(pub_aux);
	}
public :
	std::string getFileCERT()
	{
		return this->fileCERT;
	}
	void setCRL(string CRL)
	{
		this->fileCRL=CRL;
	}
	Keys(string filePriv, string fileCERT)
	{
		ByteQueue  certin;
		this->filePriv=filePriv;
		this->fileCERT=fileCERT;
		this->extractPrivateKey();
		FileSource file(this->fileCERT.c_str(), true /*pumpAll*/);
		file.TransferTo(certin);
		certin.MessageEnd();
		this->GetPublicKeyFromCert(certin);
	}
	Keys(string fileCERT)
	{
		ByteQueue  certin	;
		this->fileCERT=fileCERT;
		FileSource file(this->fileCERT.c_str(), true /*pumpAll*/);
		file.TransferTo(certin);
		certin.MessageEnd();
		this->GetPublicKeyFromCert(certin);
	}
	Keys(string cert, int a)
	{
		ByteQueue aux;
		aux.Put((byte *)cert.c_str(), cert.size());
		this->GetPublicKeyFromCert(aux);
	}
	string SignMsg(string in )
	{
		try
		{
			AutoSeededRandomPool rng;
			RSASS<PSS, SHA256>::Signer signer(priv);
			SecByteBlock signature(signer.SignatureLength());
			size_t signatureLen=signer.SignMessage(rng,(byte *)in.c_str(), in.length(),signature);
			signature.resize(signatureLen);
			string result((char *)signature.data(), signature.size());
			return result;
		}
		catch(CryptoPP::Exception &ec)
		{
			cout << "Sign" << ec.what() << endl;
			return "";
		}
	}
	bool checkDateAndCRL(CryptoPP::BufferedTransformation & certin)
	{
		string st, str, issuer, date , date2,now, publick;
		sqlite3 *db=NULL;
		sqlite3_stmt *stmt=NULL;
		//char alterar[47], *sql_alterar;
		int rc=0;
		stringstream oss,oss2;
		OID sigAlgOID;
		BERSequenceDecoder x509Cert(certin);
		BERSequenceDecoder tbsCert(x509Cert);
		// ASN.1 from RFC 3280
		// TBSCertificate  ::=  SEQUENCE  {
		// version         [0]  EXPLICIT Version DEFAULT v1,
		// consume the context tag on the version
		BERGeneralDecoder context(tbsCert,0xa0);
		word32 ver;
		// only want a v3 cert
		BERDecodeUnsigned<word32>(context,ver,INTEGER,2,2);
		// serialNumber         CertificateSerialNumber,
		Integer serial;
		serial.BERDecode(tbsCert);
		string aux;
		ifstream arq(this->fileCRL);
		oss2 << serial;
		if(arq.is_open())
		{
			while(std::getline(arq, aux))
			{
				if(!std::strncmp(aux.c_str(),oss2.str().c_str(),aux.size()))
				{
					arq.close();
					return false;
				}
			}
			arq.close();
		}
		BERSequenceDecoder sigAlg(x509Cert);
		sigAlg.SkipAll();
		ByteQueue d;
		// issuer               Name,
		BERSequenceDecoder issuerName(tbsCert);
		issuerName.SkipAll();
		// validity             Validity,
		BERSequenceDecoder validity(tbsCert);
		byte val[sizeof(validity)];
		validity.CopyTo(d,sizeof(validity));
		d.Get(val, sizeof(d));
		oss  << val;
		date= oss.str();
		date2.append(date);
		date2.erase(date2.begin()+14, date2.end());
		date2.erase(0,2);
		date.erase(0, 17);
		date.erase(date.begin()+12, date.end());
		rc = sqlite3_open("./date.db", &db);
		if( rc )
			cout << "Can't open database: " << sqlite3_errmsg(db) << endl;

		string select ("SELECT strftime('%Y%m%d%H%M%S','now');");
		rc=sqlite3_prepare_v2(db, select.c_str(), -1, &stmt, NULL);
		if( rc != SQLITE_OK )
		{
			cout << "Consulta sem resultado" << endl;
			sqlite3_close(db);
		}

		rc=sqlite3_step(stmt);
		if(rc!=SQLITE_DONE)
		{
			now=reinterpret_cast<const char *>(sqlite3_column_text(stmt,0));
		}
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		now.erase(0,2);
		if(std::strncmp(now.c_str(), date2.c_str(), now.size())<0)
		{
			std::cerr << date <<" " << now << std::endl;
			return false;
		}
		if(std::strncmp(now.c_str(), date.c_str(), now.size())>0)
		{
			std::cerr << date2 <<" " << now << std::endl;
			return false;
		}
		validity.SkipAll();
		tbsCert.SkipAll();
		x509Cert.SkipAll();
		return true;
	}
	bool VerifySignCert(string in )
	{
		ByteQueue googleq2, googletbs, googleq;
		SecByteBlock certSignature;
		googleq2.Put((byte *)in.c_str(), in.size());
		googleq.Put((byte *)in.c_str(), in.size());
		if(!this->checkDateAndCRL(googleq2))
		{
			std::cerr << "Cert receveid is invalid" << std::endl;
			return false;
		}
		try {

			// first, extract the data that the signature covers
			BERSequenceDecoder x509Cert(googleq);
			BERSequenceDecoder tbsCert(x509Cert);
			DERSequenceEncoder tbsEnc(googletbs);
			tbsCert.TransferAllTo(tbsEnc);
			tbsEnc.MessageEnd();
			// find the algorithm used to sign the data
			BERSequenceDecoder sigAlg(x509Cert);
			//sigAlgOID.BERDecode(sigAlg);
			sigAlg.SkipAll();
			// extract the actual signature
			unsigned int unused = 0;
			BERDecodeBitString(x509Cert,certSignature,unused);
			x509Cert.SkipAll();
		}catch(std::exception &e){
			cerr << "Error decoding the certificate for signature verification." << endl;
			return false;
		}
		PK_VerifierPtr verifier=PK_VerifierPtr(new RSASS<PKCS1v15,CryptoPP::SHA256>::Verifier(this->pub));
		CryptoPP::SignatureVerificationFilter vf(*verifier);
		try {
			vf.Put(certSignature,certSignature.size());
			googletbs.TransferAllTo(vf);
			vf.MessageEnd();
		}catch(std::exception &e)
		{
			cerr << "Caught an exception while verifying the signature:" << endl;
			cerr << "\t" << e.what() << endl;
			return false;
		}
		if(vf.GetLastResult())
		{
			cout << "The signature verified." << endl;
			return true;
		}
		return false;
	}

	bool VerifySignMsg(string in )
	{
		try
		{
			RSASS<PSSR, SHA256>::Verifier verifier(pub);
			string recovered;
			StringSource ss2(in, true,
					new SignatureVerificationFilter(
							verifier,
							new StringSink(recovered),
							SignatureVerificationFilter::THROW_EXCEPTION |
							SignatureVerificationFilter::PUT_MESSAGE
					) // SignatureVerificationFilter
			); // StringSource
			return true;
		}
		catch(std::exception &e)
		{
			cerr << e.what() << endl;
			return false;
		}
	}
};

/*
 * class that converts text to hexadecimal
 */
class Converter
{
private :
	string IN, OUT;
public :
	Converter(string IN)
{
		this->IN=IN;
}
	string EncodeHex()
	{
		this->OUT.clear();
		StringSource ss(this->IN, true,
				new CryptoPP::HexEncoder(new StringSink(this->OUT))
		);
		return this->OUT;
	}
	string DecodeHex()
	{
		this->OUT.clear();
		StringSource ss(this->IN, true,
				new CryptoPP::HexDecoder(new StringSink(this->OUT))
		);
		return this->OUT;
	}
	~Converter()
	{
		this->OUT.clear();
		this->IN.clear();
	}
};
/*
 * Class responsible for Diffie-Hellman
 */
class Agree
{
	DH dh;
	Integer p, q, g;
	string priv,pub,  secretText;
	SecByteBlock Kpriv, Kpub,secret, symetricKey;
	string OtherPub;
public :
	void setOtherPub(string OtherPub)
	{
		this->OtherPub=OtherPub;
	}


	Agree(Integer p, Integer q, Integer g)
	{
		this->p=p;
		this->q=q;
		this->g=g;
		dh.AccessGroupParameters().Initialize(p,q,g);
	}
	std::string getSecret()
	{
		return this->secretText;
	}

	void SecToString()
	{
		try
		{
			pub.clear();
			AutoSeededRandomPool rng;

			SecByteBlock Kpu(dh.PublicKeyLength());
			SecByteBlock Kpr(dh.PrivateKeyLength());
			dh.GenerateKeyPair(rng,Kpr, Kpu);
			this->Kpriv=Kpr;
			this->Kpub=Kpu;
			StringSource ss(this->Kpub,this->Kpub.size(), true,
					new CryptoPP::Base64Encoder(
							new StringSink(pub), false
					)
			);
			StringSource ss1(	this->Kpriv,	this->Kpriv.size(), true,
					new CryptoPP::Base64Encoder(
							new StringSink(priv), false
					)
			);
			priv.push_back('\0');
		}
		catch(CryptoPP::Exception &ec)
		{
			cerr << ec.what() << endl;
		}
	}
	bool GenerateSecret()
	{

		string aux, result;
		result.clear();
		aux.clear();
		StringSource ss(OtherPub, true,
				new CryptoPP::Base64Decoder(
						new StringSink(aux)
				)
		);
		SecByteBlock opub((byte *)aux.data(), dh.PublicKeyLength());
		SecByteBlock as(dh.AgreedValueLength());

		if(dh.Agree(as, Kpriv, opub)==true)
		{
			this->secret=as;
			Integer sec;
			sec.Decode(secret, secret.SizeInBytes());
			stringstream oss;
			oss << sec;
			this->secretText=oss.str();
			SecByteBlock key(SHA256::DIGESTSIZE);
			SHA256().CalculateDigest(key,  secret, secret.size());
			this->symetricKey=key;
			return true;
		}

		return false;

	}
	string getPublicKeyDH()
	{
		return this->pub;
	}
	string getPrivateKeyDH()
	{
		return priv;
	}
	string encode(string textPlan)
	{
		string retorno;
		ECB_Mode<AES>::Encryption enc(symetricKey,16);
		StringSource ss(textPlan, true,
				new StreamTransformationFilter(enc,
						new StringSink(retorno)
				)
		);
		return retorno;
	}
	string decode(string cypherText)
	{

		string aux, retorno;
		ECB_Mode<AES>::Decryption dec(symetricKey,16);
		StringSource ss1(cypherText, true,
				new StreamTransformationFilter(dec,
						new StringSink(retorno),
						StreamTransformationFilter::DEFAULT_PADDING
				)
		);
		return retorno;
	}
};
#endif /* DHSECURITY_HPP_ */
