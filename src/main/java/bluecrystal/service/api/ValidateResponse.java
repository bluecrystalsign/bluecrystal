package bluecrystal.service.api;

import java.util.Map;
import java.util.TreeMap;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ValidateResponse {
	private String certificate;
	private String status;
	private String cn;
	private String policy;
	private String error;

	private Map<String, String> certdetails = new TreeMap<>();

	public String getPolicyoid() {
		return policyoid;
	}

	public void setPolicyoid(String policyoid) {
		this.policyoid = policyoid;
	}

	public String getPolicyversion() {
		return policyversion;
	}

	public void setPolicyversion(String policyversion) {
		this.policyversion = policyversion;
	}

	private String policyoid;
	private String policyversion;

	public ValidateResponse() {
	}

	public String getCn() {
		return cn;
	}

	public String getError() {
		return error;
	}

	public String getPolicy() {
		return policy;
	}

	public void setCn(String cn) {
		this.cn = cn;
	}

	public void setError(String error) {
		this.error = error;
	}

	public void setPolicy(String policy) {
		this.policy = policy; 
	}

	public Map<String, String> getCertdetails() {
		return certdetails;
	}

	public void setCertdetails(Map<String, String> certdetails) {
		this.certdetails = certdetails;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
}