package am.ysu.identity.dto.response;

public class OkStatus
{
    public final int status;

    public OkStatus() {
        this.status = 200;
    }

    public OkStatus(int status) {
        this.status = status;
    }
}
