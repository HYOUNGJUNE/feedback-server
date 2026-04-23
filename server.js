const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3001;

// ────────────────────────────────────────────
// 1. 미들웨어 설정
// ────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." },
});
app.use("/api/", limiter);

app.use(express.static(path.join(__dirname, "public")));

// ────────────────────────────────────────────
// 2. Supabase 연결
// ────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("❌ 환경변수 SUPABASE_URL, SUPABASE_KEY를 설정해 주세요.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
console.log("✅ Supabase 연결 완료");

// ────────────────────────────────────────────
// 3. 암호화/복호화 유틸 (AES-256-GCM)
// ────────────────────────────────────────────
const ENCRYPTION_KEY = Buffer.from(
  process.env.ENCRYPTION_KEY ||
    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "hex"
);

function decryptPhone(encryptedBase64) {
  try {
    const combined = Buffer.from(encryptedBase64, "base64");
    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(combined.length - 16);
    const ciphertext = combined.subarray(12, combined.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch {
    return null;
  }
}

function maskPhone(phone) {
  if (!phone || phone.length < 8) return "***-****-****";
  return `${phone.slice(0, 3)}-****-${phone.slice(-4)}`;
}

// ────────────────────────────────────────────
// 4. API 엔드포인트
// ────────────────────────────────────────────

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── [POST] 고객 의견 접수 ──
app.post("/api/feedback", async (req, res) => {
  try {
    const { category, phone_encrypted, feedback, privacy_consent, consent_timestamp, client_info } = req.body;

    if (!category || !["개인", "법인담당자", "조합담당자"].includes(category)) {
      return res.status(400).json({ error: "구분을 선택해 주세요." });
    }
    if (!phone_encrypted || typeof phone_encrypted !== "string") {
      return res.status(400).json({ error: "휴대폰번호가 필요합니다." });
    }
    if (!feedback || typeof feedback !== "string" || feedback.trim().length < 5) {
      return res.status(400).json({ error: "의견은 5자 이상 입력해 주세요." });
    }
    if (feedback.length > 500) {
      return res.status(400).json({ error: "의견은 500자 이내로 입력해 주세요." });
    }
    if (!privacy_consent) {
      return res.status(400).json({ error: "개인정보 수집 동의가 필요합니다." });
    }

    const id = `FB-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

    const { error } = await supabase.from("feedback").insert({
      id,
      category,
      phone_encrypted,
      feedback: feedback.trim(),
      privacy_consent: true,
      consent_timestamp: consent_timestamp || new Date().toISOString(),
      status: "new",
      client_info: client_info || null,
    });

    if (error) throw error;

    console.log(`📩 새 의견 접수: ${id}`);
    res.status(201).json({ success: true, id });
  } catch (err) {
    console.error("❌ 의견 접수 오류:", err.message);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

// ── [GET] 의견 목록 조회 ──
app.get("/api/feedback", async (req, res) => {
  try {
    const { status, search, page = 1, limit = 20, order = "DESC" } = req.query;

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const offset = (pageNum - 1) * limitNum;

    // 전체 건수 조회
    const { data: allData } = await supabase
      .from("feedback")
      .select("status");

    const counts = {
      all: allData ? allData.length : 0,
      new: allData ? allData.filter((d) => d.status === "new").length : 0,
      reviewing: allData ? allData.filter((d) => d.status === "reviewing").length : 0,
      resolved: allData ? allData.filter((d) => d.status === "resolved").length : 0,
    };

    // 목록 쿼리 빌드
    let query = supabase
      .from("feedback")
      .select("id, category, phone_encrypted, feedback, privacy_consent, consent_timestamp, status, created_at, updated_at")
      .order("created_at", { ascending: order.toUpperCase() === "ASC" })
      .range(offset, offset + limitNum - 1);

    if (status && ["new", "reviewing", "resolved"].includes(status)) {
      query = query.eq("status", status);
    }

    if (search && search.trim()) {
      const q = search.trim();
      query = query.or(`feedback.ilike.%${q}%,id.ilike.%${q}%`);
    }

    const { data: rows, error } = await query;
    if (error) throw error;

    const items = (rows || []).map((row) => {
      const decrypted = decryptPhone(row.phone_encrypted);
      return {
        id: row.id,
        category: row.category,
        feedback: row.feedback,
        privacy_consent: row.privacy_consent,
        consent_timestamp: row.consent_timestamp,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
        phone_masked: maskPhone(decrypted),
      };
    });

    const total = items.length;
    res.json({
      items,
      pagination: { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(counts.all / limitNum) },
      counts,
    });
  } catch (err) {
    console.error("❌ 목록 조회 오류:", err.message);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

// ── [GET] 의견 상세 조회 ──
app.get("/api/feedback/:id", async (req, res) => {
  try {
    const { data: row, error } = await supabase
      .from("feedback")
      .select("*")
      .eq("id", req.params.id)
      .single();

    if (error || !row) {
      return res.status(404).json({ error: "해당 의견을 찾을 수 없습니다." });
    }

    const decrypted = decryptPhone(row.phone_encrypted);
    res.json({
      id: row.id,
      category: row.category,
      feedback: row.feedback,
      privacy_consent: row.privacy_consent,
      consent_timestamp: row.consent_timestamp,
      status: row.status,
      client_info: row.client_info,
      created_at: row.created_at,
      updated_at: row.updated_at,
      phone_decrypted: decrypted,
      phone_masked: maskPhone(decrypted),
    });
  } catch (err) {
    console.error("❌ 상세 조회 오류:", err.message);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

// ── [PATCH] 상태 변경 ──
app.patch("/api/feedback/:id/status", async (req, res) => {
  try {
    const { status } = req.body;
    if (!["new", "reviewing", "resolved"].includes(status)) {
      return res.status(400).json({ error: "유효하지 않은 상태값입니다." });
    }

    const { error } = await supabase
      .from("feedback")
      .update({ status, updated_at: new Date().toISOString() })
      .eq("id", req.params.id);

    if (error) throw error;

    console.log(`🔄 상태 변경: ${req.params.id} → ${status}`);
    res.json({ success: true, id: req.params.id, status });
  } catch (err) {
    console.error("❌ 상태 변경 오류:", err.message);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

// ── [DELETE] 의견 삭제 ──
app.delete("/api/feedback/:id", async (req, res) => {
  try {
    const { error } = await supabase
      .from("feedback")
      .delete()
      .eq("id", req.params.id);

    if (error) throw error;

    console.log(`🗑️ 의견 삭제: ${req.params.id}`);
    res.json({ success: true, id: req.params.id });
  } catch (err) {
    console.error("❌ 삭제 오류:", err.message);
    res.status(500).json({ error: "서버 오류가 발생했습니다." });
  }
});

// ────────────────────────────────────────────
// 5. 서버 시작
// ────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 서버 시작: http://localhost:${PORT}`);
  console.log(`📋 고객 폼:   http://localhost:${PORT}/customer-form.html`);
  console.log(`🔧 관리자:    http://localhost:${PORT}/admin.html`);
});
