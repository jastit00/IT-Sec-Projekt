--
-- PostgreSQL database dump
--

-- Dumped from database version 17.4 (Debian 17.4-1.pgdg120+2)
-- Dumped by pg_dump version 17.4 (Debian 17.4-1.pgdg120+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: incident_detector_bruteforceincident; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.incident_detector_bruteforceincident (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    src_ip_address inet NOT NULL,
    username character varying(32) NOT NULL,
    reason text NOT NULL,
    attempts integer NOT NULL,
    "timeDelta" character varying(32) NOT NULL,
    successful integer NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL,
    incident_type character varying(16) NOT NULL
);


ALTER TABLE public.incident_detector_bruteforceincident OWNER TO test;

--
-- Name: incident_detector_bruteforceincident_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.incident_detector_bruteforceincident ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.incident_detector_bruteforceincident_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: incident_detector_concurrentloginincident; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.incident_detector_concurrentloginincident (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    src_ip_address inet NOT NULL,
    username character varying(32) NOT NULL,
    reason text NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL,
    incident_type character varying(16) NOT NULL
);


ALTER TABLE public.incident_detector_concurrentloginincident OWNER TO test;

--
-- Name: incident_detector_configincident; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.incident_detector_configincident (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    src_ip_address inet NOT NULL,
    username character varying(32) NOT NULL,
    reason text NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL,
    incident_type character varying(16) NOT NULL
);


ALTER TABLE public.incident_detector_configincident OWNER TO test;

--
-- Name: incident_detector_configincident_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.incident_detector_configincident ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.incident_detector_configincident_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: incident_detector_ddosincident; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.incident_detector_ddosincident (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    dst_ip_address inet NOT NULL,
    "timeDelta" character varying(32) NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL,
    incident_type character varying(16) NOT NULL,
    packets integer NOT NULL,
    protocol character varying(8) NOT NULL,
    reason text NOT NULL,
    sources text NOT NULL
);


ALTER TABLE public.incident_detector_ddosincident OWNER TO test;

--
-- Name: incident_detector_ddosincident_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.incident_detector_ddosincident ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.incident_detector_ddosincident_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: incident_detector_dosincident; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.incident_detector_dosincident (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    src_ip_address inet NOT NULL,
    dst_ip_address inet NOT NULL,
    "timeDelta" character varying(32) NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL,
    incident_type character varying(16) NOT NULL,
    packets integer NOT NULL,
    protocol character varying(8) NOT NULL,
    reason text NOT NULL
);


ALTER TABLE public.incident_detector_dosincident OWNER TO test;

--
-- Name: incident_detector_dosincident_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.incident_detector_dosincident ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.incident_detector_dosincident_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: incident_detector_loginincident_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.incident_detector_concurrentloginincident ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.incident_detector_loginincident_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: incident_detector_relatedlog; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.incident_detector_relatedlog (
    id bigint NOT NULL,
    bruteforce_incident_id bigint,
    concurrent_login_incident_id bigint,
    config_incident_id bigint,
    ddos_incident_id bigint,
    dos_incident_id bigint,
    netfilter_packet_id bigint,
    user_login_id bigint,
    user_logout_id bigint,
    usys_config_id bigint
);


ALTER TABLE public.incident_detector_relatedlog OWNER TO test;

--
-- Name: incident_detector_relatedlog_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.incident_detector_relatedlog ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.incident_detector_relatedlog_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: log_processor_netfilterpackets; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.log_processor_netfilterpackets (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    src_ip_address inet NOT NULL,
    dst_ip_address inet NOT NULL,
    protocol character varying(8) NOT NULL,
    event_type character varying(16) NOT NULL,
    count integer NOT NULL,
    severity character varying(16) NOT NULL
);


ALTER TABLE public.log_processor_netfilterpackets OWNER TO test;

--
-- Name: log_processor_netfilterpackets_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.log_processor_netfilterpackets ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.log_processor_netfilterpackets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: log_processor_uploadedlogfile; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.log_processor_uploadedlogfile (
    id bigint NOT NULL,
    filename character varying(255) NOT NULL,
    file_hash character varying(64) NOT NULL,
    source character varying(100) NOT NULL,
    uploaded_by character varying(150),
    uploaded_at timestamp with time zone NOT NULL,
    status character varying(16) NOT NULL,
    entries_created integer NOT NULL,
    incident_counts jsonb,
    incidents_created_total integer NOT NULL
);


ALTER TABLE public.log_processor_uploadedlogfile OWNER TO test;

--
-- Name: log_processor_uploadedlogfile_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.log_processor_uploadedlogfile ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.log_processor_uploadedlogfile_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: log_processor_userlogin; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.log_processor_userlogin (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    username character varying(32) NOT NULL,
    src_ip_address inet NOT NULL,
    terminal character varying(4),
    result character varying(16) NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL
);


ALTER TABLE public.log_processor_userlogin OWNER TO test;

--
-- Name: log_processor_userlogin_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.log_processor_userlogin ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.log_processor_userlogin_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: log_processor_userlogout; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.log_processor_userlogout (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    username character varying(32) NOT NULL,
    terminal character varying(4),
    result character varying(16) NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL
);


ALTER TABLE public.log_processor_userlogout OWNER TO test;

--
-- Name: log_processor_userlogout_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.log_processor_userlogout ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.log_processor_userlogout_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: log_processor_usysconfig; Type: TABLE; Schema: public; Owner: test
--

CREATE TABLE public.log_processor_usysconfig (
    id bigint NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    "table" character varying(32) NOT NULL,
    action character varying(16) NOT NULL,
    key character varying(100),
    value text,
    condition character varying(64),
    terminal character varying(32) NOT NULL,
    result character varying(16) NOT NULL,
    event_type character varying(16) NOT NULL,
    severity character varying(16) NOT NULL
);


ALTER TABLE public.log_processor_usysconfig OWNER TO test;

--
-- Name: log_processor_usysconfig_id_seq; Type: SEQUENCE; Schema: public; Owner: test
--

ALTER TABLE public.log_processor_usysconfig ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.log_processor_usysconfig_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: incident_detector_bruteforceincident incident_detector_bruteforceincident_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_bruteforceincident
    ADD CONSTRAINT incident_detector_bruteforceincident_pkey PRIMARY KEY (id);


--
-- Name: incident_detector_configincident incident_detector_configincident_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_configincident
    ADD CONSTRAINT incident_detector_configincident_pkey PRIMARY KEY (id);


--
-- Name: incident_detector_ddosincident incident_detector_ddosincident_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_ddosincident
    ADD CONSTRAINT incident_detector_ddosincident_pkey PRIMARY KEY (id);


--
-- Name: incident_detector_dosincident incident_detector_dosincident_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_dosincident
    ADD CONSTRAINT incident_detector_dosincident_pkey PRIMARY KEY (id);


--
-- Name: incident_detector_concurrentloginincident incident_detector_loginincident_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_concurrentloginincident
    ADD CONSTRAINT incident_detector_loginincident_pkey PRIMARY KEY (id);


--
-- Name: incident_detector_relatedlog incident_detector_relatedlog_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_relatedlog_pkey PRIMARY KEY (id);


--
-- Name: log_processor_netfilterpackets log_processor_netfilterpackets_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.log_processor_netfilterpackets
    ADD CONSTRAINT log_processor_netfilterpackets_pkey PRIMARY KEY (id);


--
-- Name: log_processor_uploadedlogfile log_processor_uploadedlogfile_file_hash_key; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.log_processor_uploadedlogfile
    ADD CONSTRAINT log_processor_uploadedlogfile_file_hash_key UNIQUE (file_hash);


--
-- Name: log_processor_uploadedlogfile log_processor_uploadedlogfile_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.log_processor_uploadedlogfile
    ADD CONSTRAINT log_processor_uploadedlogfile_pkey PRIMARY KEY (id);


--
-- Name: log_processor_userlogin log_processor_userlogin_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.log_processor_userlogin
    ADD CONSTRAINT log_processor_userlogin_pkey PRIMARY KEY (id);


--
-- Name: log_processor_userlogout log_processor_userlogout_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.log_processor_userlogout
    ADD CONSTRAINT log_processor_userlogout_pkey PRIMARY KEY (id);


--
-- Name: log_processor_usysconfig log_processor_usysconfig_pkey; Type: CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.log_processor_usysconfig
    ADD CONSTRAINT log_processor_usysconfig_pkey PRIMARY KEY (id);


--
-- Name: incident_detector_relatedl_concurrent_login_incident__4c40963a; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedl_concurrent_login_incident__4c40963a ON public.incident_detector_relatedlog USING btree (concurrent_login_incident_id);


--
-- Name: incident_detector_relatedlog_bruteforce_incident_id_e62e2cf3; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_bruteforce_incident_id_e62e2cf3 ON public.incident_detector_relatedlog USING btree (bruteforce_incident_id);


--
-- Name: incident_detector_relatedlog_config_incident_id_c6c55223; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_config_incident_id_c6c55223 ON public.incident_detector_relatedlog USING btree (config_incident_id);


--
-- Name: incident_detector_relatedlog_ddos_incident_id_b513dbef; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_ddos_incident_id_b513dbef ON public.incident_detector_relatedlog USING btree (ddos_incident_id);


--
-- Name: incident_detector_relatedlog_dos_incident_id_0ed8b159; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_dos_incident_id_0ed8b159 ON public.incident_detector_relatedlog USING btree (dos_incident_id);


--
-- Name: incident_detector_relatedlog_netfilter_packet_id_29b93cdf; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_netfilter_packet_id_29b93cdf ON public.incident_detector_relatedlog USING btree (netfilter_packet_id);


--
-- Name: incident_detector_relatedlog_user_login_id_29fc1453; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_user_login_id_29fc1453 ON public.incident_detector_relatedlog USING btree (user_login_id);


--
-- Name: incident_detector_relatedlog_user_logout_id_5b3525f6; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_user_logout_id_5b3525f6 ON public.incident_detector_relatedlog USING btree (user_logout_id);


--
-- Name: incident_detector_relatedlog_usys_config_id_da190d69; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX incident_detector_relatedlog_usys_config_id_da190d69 ON public.incident_detector_relatedlog USING btree (usys_config_id);


--
-- Name: log_processor_uploadedlogfile_file_hash_0a0d7196_like; Type: INDEX; Schema: public; Owner: test
--

CREATE INDEX log_processor_uploadedlogfile_file_hash_0a0d7196_like ON public.log_processor_uploadedlogfile USING btree (file_hash varchar_pattern_ops);


--
-- Name: incident_detector_relatedlog incident_detector_re_bruteforce_incident__e62e2cf3_fk_incident_; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_bruteforce_incident__e62e2cf3_fk_incident_ FOREIGN KEY (bruteforce_incident_id) REFERENCES public.incident_detector_bruteforceincident(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_concurrent_login_inc_4c40963a_fk_incident_; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_concurrent_login_inc_4c40963a_fk_incident_ FOREIGN KEY (concurrent_login_incident_id) REFERENCES public.incident_detector_concurrentloginincident(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_config_incident_id_c6c55223_fk_incident_; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_config_incident_id_c6c55223_fk_incident_ FOREIGN KEY (config_incident_id) REFERENCES public.incident_detector_configincident(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_ddos_incident_id_b513dbef_fk_incident_; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_ddos_incident_id_b513dbef_fk_incident_ FOREIGN KEY (ddos_incident_id) REFERENCES public.incident_detector_ddosincident(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_dos_incident_id_0ed8b159_fk_incident_; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_dos_incident_id_0ed8b159_fk_incident_ FOREIGN KEY (dos_incident_id) REFERENCES public.incident_detector_dosincident(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_netfilter_packet_id_29b93cdf_fk_log_proce; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_netfilter_packet_id_29b93cdf_fk_log_proce FOREIGN KEY (netfilter_packet_id) REFERENCES public.log_processor_netfilterpackets(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_user_login_id_29fc1453_fk_log_proce; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_user_login_id_29fc1453_fk_log_proce FOREIGN KEY (user_login_id) REFERENCES public.log_processor_userlogin(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_user_logout_id_5b3525f6_fk_log_proce; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_user_logout_id_5b3525f6_fk_log_proce FOREIGN KEY (user_logout_id) REFERENCES public.log_processor_userlogout(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: incident_detector_relatedlog incident_detector_re_usys_config_id_da190d69_fk_log_proce; Type: FK CONSTRAINT; Schema: public; Owner: test
--

ALTER TABLE ONLY public.incident_detector_relatedlog
    ADD CONSTRAINT incident_detector_re_usys_config_id_da190d69_fk_log_proce FOREIGN KEY (usys_config_id) REFERENCES public.log_processor_usysconfig(id) DEFERRABLE INITIALLY DEFERRED;


--
-- PostgreSQL database dump complete
--

