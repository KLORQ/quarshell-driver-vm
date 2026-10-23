package vmguest

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	ControlPort                    = 5500
	FrameMax                       = 64 << 20
	ProtocolVersion                = 1
	SupervisorControlCredentialDir = "/run/quarshell/supervisor-control-private"
)

type Request struct {
	Version                    uint16   `json:"version"`
	AuthToken                  string   `json:"auth_token,omitempty"`
	NextAuthToken              string   `json:"next_auth_token,omitempty"`
	RotationID                 string   `json:"rotation_id,omitempty"`
	Operation                  string   `json:"operation"`
	Argv                       []string `json:"argv,omitempty"`
	Env                        []string `json:"env,omitempty"`
	User                       string   `json:"user,omitempty"`
	RestartPolicy              string   `json:"restart_policy,omitempty"`
	Signal                     string   `json:"signal,omitempty"`
	TTY                        bool     `json:"tty,omitempty"`
	AwaitMainProcessAttachment bool     `json:"await_main_process_attachment,omitempty"`
	WorkDir                    string   `json:"workdir,omitempty"`
	Stdin                      []byte   `json:"stdin,omitempty"`
	NoLoginShell               bool     `json:"no_login_shell,omitempty"`
	Columns                    uint32   `json:"columns,omitempty"`
	Rows                       uint32   `json:"rows,omitempty"`
	SessionID                  string   `json:"session_id,omitempty"`
	Path                       string   `json:"path,omitempty"`
	Mode                       uint32   `json:"mode,omitempty"`
	Data                       []byte   `json:"data,omitempty"`
}

type Response struct {
	Version         uint16 `json:"version"`
	Error           string `json:"error,omitempty"`
	ExitCode        int    `json:"exit_code,omitempty"`
	Stdout          []byte `json:"stdout,omitempty"`
	Stderr          []byte `json:"stderr,omitempty"`
	Data            []byte `json:"data,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	PID             int    `json:"pid,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	InputOwner      bool   `json:"input_owner,omitempty"`
	WorkloadUID     uint32 `json:"workload_uid,omitempty"`
	WorkloadGID     uint32 `json:"workload_gid,omitempty"`
}

// TerminalFrame multiplexes PTY output, stdin and resize events over one
// authenticated guest control stream.
type TerminalFrame struct {
	Type       string `json:"type"`
	Data       []byte `json:"data,omitempty"`
	Columns    uint32 `json:"columns,omitempty"`
	Rows       uint32 `json:"rows,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	Signal     string `json:"signal,omitempty"`
	LostChunks uint64 `json:"lost_chunks,omitempty"`
}

func WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > FrameMax {
		return fmt.Errorf("invalid frame size %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func ReadFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > FrameMax {
		return nil, fmt.Errorf("invalid frame size %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
