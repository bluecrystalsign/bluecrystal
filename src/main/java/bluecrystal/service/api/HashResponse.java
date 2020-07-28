package bluecrystal.service.api;

import java.util.Map;
import java.util.TreeMap;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class HashResponse {
	private String hash;
	private String cn;
	private String policy;
	private String policyversion;
	private String policyoid;
	private String error;

	private Map<String, String> certdetails = new TreeMap<>();

	public String getHash() {
		return hash;
	}

	public void setHash(String hash) {
		this.hash = hash;
	}

	public String getCn() {
		return cn;
	}

	public void setCn(String cn) {
		this.cn = cn;
	}

	public String getPolicy() {
		return policy;
	}

	public void setPolicy(String policy) {
		this.policy = policy;
	}

	public String getPolicyversion() {
		return policyversion;
	}

	public void setPolicyversion(String policyversion) {
		this.policyversion = policyversion;
	}

	public String getPolicyoid() {
		return policyoid;
	}

	public void setPolicyoid(String policyoid) {
		this.policyoid = policyoid;
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

}