Implementação de um protocolo para troca de certificados digitais com autenticação múta.

Depêndencias:
	boost asio, crypto++ e sqlite3

Protocolo:
1 - Bob e Alice estabalecem um canal Diffie-Hellman;
2 - Alice envia seu certificado digital junto com a assinatura do certificado e da hash do segredo compartilhado gerado no Diffie-Hellman encriptado com a chave compartilhada utilizando o AES;
3 - Bob verifica se o certificado digital de Alice é válido verificando a lista de certificados revogados da autoridade certificadora e a data de validade, após verifica assinatura do certificado digital e obt[em a chave pública contida no certificado;
4 - Bob decifra a assinatura da mensagem que contém o certificado + hash do segredo compartilhado;
5 - Bob gera o hash do segredo compartilhado;
6 - Bob verifica a assinatura, se correspondor, Bob autentica Alice e envia mensagem no mesmo formato para Alice;
7 - Alice realiza o mesmo processo


Os certificados e as chaves públicas devem estar em formato .DER pois a Crypto++ trabalha com essa extensão  


