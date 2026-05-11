import React, { Component } from 'react';
import { Trans, withTranslation } from 'react-i18next';

import Card from '../ui/Card';
import PageTitle from '../ui/PageTitle';

import { getTextareaCommentsHighlight, syncScroll } from '../../helpers/highlightTextareaComments';
import { COMMENT_LINE_DEFAULT_TOKEN } from '../../helpers/constants';
import '../ui/texareaCommentsHighlight.css';

interface TrustedFilterListProps {
    title: string;
    subtitle: string;
    placeholder: string;
    list: string[];
    onSave: (list: string[]) => void;
    onAppend: (list: string[]) => void;
    t: (...args: unknown[]) => string;
}

interface TrustedFilterListState {
    value: string;
    uploading: boolean;
}

class TrustedFilterList extends Component<TrustedFilterListProps, TrustedFilterListState> {
    highlightRef = React.createRef<HTMLTextAreaElement>();

    fileInputRef = React.createRef<HTMLInputElement>();

    state: TrustedFilterListState = {
        value: '',
        uploading: false,
    };

    componentDidMount() {
        this.setState({ value: this.props.list.join('\n') });
    }

    componentDidUpdate(prevProps: TrustedFilterListProps) {
        if (prevProps.list !== this.props.list) {
            this.setState({ value: this.props.list.join('\n') });
        }
    }

    handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        this.setState({ value: e.currentTarget.value });
    };

    handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        const lines = this.state.value
            .split('\n')
            .map((l) => l.trim())
            .filter((l) => l !== '' && !l.startsWith('#'));
        this.props.onSave(lines);
    };

    handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) {
            return;
        }

        const reader = new FileReader();
        reader.onload = (ev) => {
            const content = ev.target?.result as string;
            const lines = content
                .split('\n')
                .map((l) => l.trim())
                .filter((l) => l !== '' && !l.startsWith('#'));

            if (lines.length === 0) {
                return;
            }

            this.setState({ uploading: true });
            try {
                this.props.onAppend(lines);
            } finally {
                this.setState({ uploading: false });
            }
        };
        reader.readAsText(file);
        e.target.value = '';
    };

    handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => syncScroll(e, this.highlightRef);

    render() {
        const { title, subtitle, placeholder, t } = this.props;
        const { value, uploading } = this.state;

        return (
            <>
                <PageTitle title={t(title)} />
                <Card subtitle={t(subtitle)}>
                    <form onSubmit={this.handleSubmit}>
                        <div className="text-edit-container mb-4">
                            <textarea
                                className="form-control font-monospace text-input"
                                value={value}
                                onChange={this.handleChange}
                                onScroll={this.handleScroll}
                                placeholder={t(placeholder)}
                            />
                            {getTextareaCommentsHighlight(
                                this.highlightRef,
                                value,
                                [COMMENT_LINE_DEFAULT_TOKEN, '!'],
                            )}
                        </div>
                        <div className="card-actions">
                            <button
                                className="btn btn-success btn-standard btn-large"
                                type="submit">
                                <Trans>apply_btn</Trans>
                            </button>
                            <button
                                className="btn btn-outline-secondary btn-standard"
                                type="button"
                                disabled={uploading}
                                onClick={() => this.fileInputRef.current?.click()}>
                                {uploading ? <Trans>processing</Trans> : <Trans>upload_file</Trans>}
                            </button>
                            <input
                                ref={this.fileInputRef}
                                type="file"
                                accept=".txt,.csv,text/plain"
                                style={{ display: 'none' }}
                                onChange={this.handleFileUpload}
                            />
                        </div>
                    </form>
                </Card>
            </>
        );
    }
}

export default withTranslation()(TrustedFilterList);
