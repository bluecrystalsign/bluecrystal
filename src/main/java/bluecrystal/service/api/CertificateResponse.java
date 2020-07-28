package bluecrystal.service.api;

import java.util.Map;
import java.util.TreeMap;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class CertificateResponse {
	private String subject;
	private String cn;
	private String name;
	private String cpf;
	private String error;

	private Map<String, String> certdetails = new TreeMap<>();

	public String getCn() {
		return cn;
	}

	public void setCn(String cn) {
		this.cn = cn;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public String getCpf() {
		return cpf;
	}

	public void setCpf(String cpf) {
		this.cpf = cpf;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public Map<String, String> getCertdetails() {
		return certdetails;
	}

	public void setCertdetails(Map<String, String> certdetails) {
		this.certdetails = certdetails;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}