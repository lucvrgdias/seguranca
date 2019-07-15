/*
 * main.cpp
 *
 *  Created on: Jul 1, 2019
 *      Author: lucas
 */

#include "DHSecurity.hpp"
int main(int argc, char**argv )
{
	if(argc<5)
	{
		std::cerr << "args [CERT-CA CERT PRIV CRL PORT]  from SERVER or [PORT and ADDRESS ] from CLIENT";
		return 1;
	}
	ifstream file_one(argv[2]);
	string cert;
	FileSource file3(file_one, true, new StringSink(cert));
	HASHER *hasher=nullptr;
	Converter *c=nullptr;
	/*
	 * P,G e Q definidos em RFC
	 */
	Keys *ca=nullptr,*pair_cert=nullptr, *other=nullptr;
	ca=new Keys(argv[1]);
	if(ca==nullptr)
	{
		std::cerr <<  "Error in CA certificate" << std::endl;
		return 1;
	}
	ca->setCRL(argv[4]);
	Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
			"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
			"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
			"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
			"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
			"DF1FB2BC2E4A4371");
	Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
			"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
			"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
			"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
			"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
			"855E6EEB22B3B2E5");

	Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");
	if(argc==6)
	{
		Agree BobDH(p,q,g);
		pair_cert = new Keys(argv[3],argv[2]);
		if(pair_cert==nullptr)
		{
			std::cerr << "Error in Pair Keys" << std::endl;
			return 1;
		}
		pair_cert->setCRL(argv[4]);
		std::cout << argv[5] << std::endl;
		Server Bob(static_cast<int>(*(argv[5])));
		BobDH.SecToString();
		std::cout << "Bob DH: " << BobDH.getPublicKeyDH() << std::endl;
		bool flag_sock=true;
		while(flag_sock)
		{
			try
			{
				if(Bob.open())
				{
					Bob.write_line(BobDH.getPublicKeyDH());
					string alicePublic=Bob.read_line();
					std::cout << "Alice DH " << alicePublic << std::endl;
					BobDH.setOtherPub(alicePublic);
					c=new Converter(cert);

					if(BobDH.GenerateSecret())
					{
						std::cout <<'\n'  << "Secret: " << BobDH.getSecret() << '\n' << std::endl;
						hasher=new HASHER(BobDH.getSecret());
						string MSG(c->EncodeHex());
						MSG.push_back('\n');
						c=new Converter(BobDH.encode(pair_cert->SignMsg(cert+hasher->generateHash<CryptoPP::SHA256>())));
						MSG.append(c->EncodeHex());
						string AliceR=Bob.read_line();
						std::cout << "CERT + Encrypted sign CERT + HASH Secret with Secret Shared " << AliceR << std::endl;
						size_t len_cert = AliceR.find('\n');
						string AliceCert=AliceR.substr(0, len_cert);
						string SignatureCert=AliceR.substr(len_cert);
						c=new Converter(AliceCert);
						string a = c->DecodeHex();
						if(ca->VerifySignCert(a))
						{
							other=new Keys(a,0);
							c=new Converter(SignatureCert);
							string SignandHash=BobDH.decode(c->DecodeHex());
							if(other->VerifySignMsg(a+hasher->generateHash<CryptoPP::SHA256>()+SignandHash))
							{
								std::cout << "Alice Authenticate" << std::endl;
								Bob.write_line(MSG);
								ofstream outputFile;
								outputFile.open("alice.cert.der");
								outputFile << a;
							}
							else
							{
								std::cout << "Alice Message isn't Authenticate" << std::endl;
								Bob.close();
							}
						}
						else
						{
							std::cout << "Alice isn't Authenticate" << std::endl;
							Bob.close();
						}
					}
					flag_sock=false;
				}
				Bob.close();
			}
			catch(std::exception &ec)
			{
				std::cout << ec.what() << std::endl;
			}
		}
		return 1;
	}
	if(argc==7)
	{
		pair_cert = new Keys(argv[3],argv[2]);
		if(pair_cert==nullptr)
		{
			std::cerr << "Error in Pair Keys" << std::endl;
			return 1;
		}
		pair_cert->setCRL(argv[4]);
		Agree Alice(p,q,g);
		Client client(argv[6],static_cast<int>(*(argv[5])));
		Alice.SecToString();
		try
		{
			if(client.connect())
			{
				client.write_line(Alice.getPublicKeyDH());
				string otherb = client.read_line();
				Alice.setOtherPub(otherb);
				std::cout << " Bob DH "<< otherb << std::endl;
				if(Alice.GenerateSecret())
				{
					std::cout <<'\n'  << "Secret: " << Alice.getSecret() << '\n' << std::endl;
					hasher=new HASHER(Alice.getSecret());
					c=new Converter(cert);
					string MSG(c->EncodeHex());
					MSG.push_back('\n');
					c=new Converter(Alice.encode(pair_cert->SignMsg(cert+hasher->generateHash<CryptoPP::SHA256>())));
					MSG.append(c->EncodeHex());
					client.write_line(MSG);
					string BobCert=client.read_line();
					std::cout << "CERT + Encrypted sign CERT + HASH Secret with Secret Shared " << BobCert << std::endl;
					if(BobCert.size())
					{
						size_t len_cert = BobCert.find('\n');
						string AliceCert=BobCert.substr(0, len_cert);
						string SignatureCert=BobCert.substr(len_cert);
						c=new Converter(AliceCert);
						string a = c->DecodeHex();
						//std::cout << '\n' << '\n' << '\n'<< '\n' << '\n'<< "CERT " <<  a << std::endl;
						if(ca->VerifySignCert(a))
						{
							other=new Keys(a,0);
							c=new Converter(SignatureCert);
							string SignandHash=Alice.decode(c->DecodeHex());
							if(other->VerifySignMsg(a+hasher->generateHash<CryptoPP::SHA256>()+SignandHash))
							{
								ofstream outputFile;
								outputFile.open("bob.cert.der");
								outputFile << a;
								std::cout << "Bob is Authenticate" << std::endl;
							}
							else
							{
								std::cout << "Bob Message isn't Authenticate" << std::endl;
								client.close();
							}
						}
						else
						{
							std::cout << "Bob isn't Authenticate" << std::endl;
							client.close();
						}
					}
					//std::cout << '\n' << '\n' <<  BobCert << std::endl;
				}
				client.close();
			}
		}
		catch(std::exception &ec)
		{
			std::cout << ec.what() << std::endl;
		}
	}
	return 0;
}


