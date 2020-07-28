/*
    Blue Crystal: Document Digital Signature Tool
    Copyright (C) 2007-2015  Sergio Leal

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package bluecrystal.service.service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

import bluecrystal.domain.SignCompare;
import bluecrystal.domain.SignCompare2;
import bluecrystal.domain.SignPolicyRef;

public interface CryptoService {

	public abstract byte[] hashSignedAttribSha1(byte[] origHash,
			Date signingTime, X509Certificate x509) throws Exception;

	public abstract byte[] hashSignedAttribSha256(byte[] origHash,
			Date signingTime, X509Certificate x509) throws Exception;

	public abstract byte[] extractSignature(byte[] sign) throws Exception;

	public abstract byte[] composeBodySha1(byte[] sign, X509Certificate c,
			byte[] origHash, Date signingTime) throws Exception;

	public abstract byte[] composeBodySha256(byte[] sign, X509Certificate c,
			byte[] origHash, Date signingTime) throws Exception;
	
	public byte[] calcSha256(byte[] content) throws NoSuchAlgorithmException;

	public byte[] calcSha1(byte[] content) throws NoSuchAlgorithmException;
	
	public SignCompare extractSignCompare(byte[] sign) throws Exception;
	public SignPolicyRef extractVerifyRefence(byte[] policy) throws IOException, ParseException;
	public boolean validateSignatureByPolicy(SignPolicyRef spr, SignCompare sc);
	
	public int  validateSign(byte[] sign, byte[] content,
			Date dtSign, boolean verifyCRL) throws Exception;

	SignCompare2 extractSignCompare2(byte[] sign) throws Exception;
	
	public boolean validateSignatureByPolicy(byte[] sign, byte[] ps) throws Exception;

	int validateSignByContent(byte[] signCms, byte[] content, Date dtSign, boolean verifyCRL) throws Exception;
}